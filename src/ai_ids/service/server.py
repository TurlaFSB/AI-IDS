"""Loading a verified model and running the service."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from typing import Any

from flask import Flask

from ai_ids.registry import load_detector, read_manifest
from ai_ids.service.app import create_app
from ai_ids.service.settings import ServiceSettings

logger = logging.getLogger(__name__)

LOOPBACK_NAMES = {"localhost"}


def is_loopback(host: str) -> bool:
    if host in LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def build_app(
    model_dir: Path, settings: ServiceSettings, *, hmac_key: bytes | None = None
) -> Flask:
    """Load the model through the integrity-checked registry and build the application."""
    detector = load_detector(model_dir, hmac_key=hmac_key)  # verifies digest and signature
    detector.set_inference_threads(1)
    manifest = read_manifest(model_dir)
    info: dict[str, Any] = {
        "artifact_sha256": manifest.get("sha256"),
        "trained_at": manifest.get("created_at"),
        "signed": bool(manifest.get("signature")),
    }
    return create_app(detector, settings, model_info=info)


def serve(app: Flask, host: str, port: int, *, allow_remote: bool, threads: int = 4) -> None:
    """Run with waitress. Binding beyond loopback needs an explicit opt-in and a TLS proxy."""
    if not is_loopback(host) and not allow_remote:
        raise SystemExit(
            f"refusing to bind {host}: the service has no TLS of its own. Bind to 127.0.0.1 "
            "behind a TLS-terminating proxy, or pass --allow-remote if you have one in front."
        )
    from waitress import serve as waitress_serve

    waitress_serve(app, host=host, port=port, threads=threads, ident="ai-ids")
