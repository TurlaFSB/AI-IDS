"""Service configuration, read from the environment (12-factor).

Secrets come only from environment variables; they are never logged and never part of the repo.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass

MIN_KEY_LENGTH = 16
MAX_TRUSTED_PROXIES = 5
DEFAULT_CONTEXT_FIELDS = ("flow_id", "source_ip", "destination_ip", "source_port", "timestamp")


class SettingsError(ValueError):
    """Raised for missing or unsafe configuration; messages never include secret values."""


def _positive_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError:
        raise SettingsError(f"{name} must be an integer") from None
    if value < 1:
        raise SettingsError(f"{name} must be positive")
    return value


def _proxy_count(env: Mapping[str, str]) -> int:
    raw = env.get("AI_IDS_TRUSTED_PROXIES")
    if raw is None:
        return 0
    try:
        return int(raw)
    except ValueError:
        raise SettingsError("AI_IDS_TRUSTED_PROXIES must be an integer") from None


@dataclass(frozen=True)
class ServiceSettings:
    api_key: str
    read_key: str
    max_flows_per_request: int = 1000
    max_body_bytes: int = 5_000_000
    rate_limit_per_minute: int = 120
    alert_buffer: int = 500
    context_fields: tuple[str, ...] = DEFAULT_CONTEXT_FIELDS
    behind_tls: bool = False
    trusted_proxies: int = 0

    def __post_init__(self) -> None:
        for name, key in (("API key", self.api_key), ("read key", self.read_key)):
            if len(key) < MIN_KEY_LENGTH:
                raise SettingsError(f"the {name} must be at least {MIN_KEY_LENGTH} characters")
        if self.api_key == self.read_key:
            raise SettingsError("the API key and the read key must differ")
        for name in ("max_flows_per_request", "max_body_bytes", "rate_limit_per_minute"):
            if getattr(self, name) < 1:
                raise SettingsError(f"{name} must be positive")
        if self.alert_buffer < 1:
            raise SettingsError("alert_buffer must be positive")
        if not 0 <= self.trusted_proxies <= MAX_TRUSTED_PROXIES:
            raise SettingsError(f"trusted_proxies must be between 0 and {MAX_TRUSTED_PROXIES}")

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> ServiceSettings:
        source = os.environ if env is None else env
        missing = [n for n in ("AI_IDS_API_KEY", "AI_IDS_READ_KEY") if not source.get(n)]
        if missing:
            raise SettingsError(f"missing required environment variable(s): {', '.join(missing)}")
        return cls(
            api_key=source["AI_IDS_API_KEY"],
            read_key=source["AI_IDS_READ_KEY"],
            max_flows_per_request=_positive_int(source, "AI_IDS_MAX_FLOWS", 1000),
            rate_limit_per_minute=_positive_int(source, "AI_IDS_RATE_LIMIT_PER_MINUTE", 120),
            alert_buffer=_positive_int(source, "AI_IDS_ALERT_BUFFER", 500),
            behind_tls=source.get("AI_IDS_BEHIND_TLS", "").lower() in {"1", "true", "yes"},
            trusted_proxies=_proxy_count(source),
        )
