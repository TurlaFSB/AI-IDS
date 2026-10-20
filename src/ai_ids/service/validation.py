"""Strict validation of scoring requests (OWASP ASVS V5).

Validation messages name fields and positions but never echo values supplied by the client.
"""

from __future__ import annotations

import math
from collections.abc import Sequence
from typing import Any

import pandas as pd

from ai_ids.service.errors import RequestError
from ai_ids.service.settings import ServiceSettings

MAX_ABS_VALUE = 1e15
MAX_CONTEXT_TEXT = 64


def _bad(message: str) -> RequestError:
    return RequestError(422, "invalid_request", message)


def _names(names: Sequence[str], limit: int = 5) -> str:
    shown = ", ".join(n[:40] for n in list(names)[:limit])
    return shown + (f" (+{len(names) - limit} more)" if len(names) > limit else "")


def _feature_value(value: object, index: int, name: str) -> float:
    if value is None:
        return math.nan  # explicit null means "missing"; the model imputes it
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise _bad(f"flow {index}: feature '{name[:40]}' must be a number or null")
    number = float(value)
    if not math.isfinite(number) or abs(number) > MAX_ABS_VALUE:
        raise _bad(f"flow {index}: feature '{name[:40]}' must be a finite number")
    return number


def _context_value(value: object, index: int, name: str) -> str | int:
    if isinstance(value, bool) or not isinstance(value, str | int):
        raise _bad(f"flow {index}: field '{name[:40]}' must be a string or integer")
    if isinstance(value, str) and (len(value) > MAX_CONTEXT_TEXT or not value.isprintable()):
        raise _bad(f"flow {index}: field '{name[:40]}' is too long or contains control characters")
    return value


def parse_flows(
    payload: Any, features: Sequence[str], settings: ServiceSettings
) -> tuple[pd.DataFrame, list[dict[str, str | int]]]:
    """Validate a scoring request body and return the feature matrix and per-flow context."""
    if not isinstance(payload, dict) or set(payload) != {"flows"}:
        raise _bad("the body must be a JSON object with exactly one key, 'flows'")
    flows = payload["flows"]
    if not isinstance(flows, list) or not flows:
        raise _bad("'flows' must be a non-empty list")
    if len(flows) > settings.max_flows_per_request:
        raise _bad(f"'flows' may contain at most {settings.max_flows_per_request} entries")

    allowed = set(features) | set(settings.context_fields)
    rows: list[list[float]] = []
    contexts: list[dict[str, str | int]] = []
    for index, flow in enumerate(flows):
        if not isinstance(flow, dict):
            raise _bad(f"flow {index} must be a JSON object")
        unknown = sorted(set(flow) - allowed)
        if unknown:
            raise _bad(f"flow {index} has unknown field(s): {_names(unknown)}")
        missing = [name for name in features if name not in flow]
        if missing:
            raise _bad(f"flow {index} is missing {len(missing)} feature(s): {_names(missing)}")
        rows.append([_feature_value(flow[name], index, name) for name in features])
        contexts.append(
            {
                name: _context_value(flow[name], index, name)
                for name in settings.context_fields
                if flow.get(name) is not None
            }
        )
    return pd.DataFrame(rows, columns=list(features)), contexts
