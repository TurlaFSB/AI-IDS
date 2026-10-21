"""The scoring service: a Flask application factory.

Security controls (OWASP ASVS L2 where applicable): bearer-key authentication with constant-time
comparison and separate read and score scopes, strict input validation, request size and batch
limits, per-client rate limiting, security headers with a strict CSP, JSON-only errors without
stack traces, structured logs that never contain payloads or keys, and no state-changing
endpoint reachable without the score key. TLS is terminated by a reverse proxy (see the runbook).
"""

from __future__ import annotations

import hmac
import logging
import re
import time
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path
from typing import Any, TypeVar, cast

from flask import Flask, Response, g, jsonify, request, send_from_directory
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from werkzeug.exceptions import HTTPException
from werkzeug.middleware.proxy_fix import ProxyFix

from ai_ids.labels import techniques_for_category
from ai_ids.models.detectors import BaseDetector
from ai_ids.service.errors import RequestError
from ai_ids.service.ratelimit import TokenBucketLimiter
from ai_ids.service.settings import ServiceSettings
from ai_ids.service.state import ServiceState
from ai_ids.service.validation import parse_flows

logger = logging.getLogger("ai_ids.service")

PACKAGE_DIR = Path(__file__).parent
STATIC_DIR = PACKAGE_DIR / "static"
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9-]{8,64}$")
MAX_ALERT_LIMIT = 200

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
)

F = TypeVar("F", bound=Callable[..., Any])


def _json_error(error: RequestError) -> Response:
    response = jsonify({"error": {"code": error.code, "message": error.message}})
    response.status_code = error.status
    for name, value in error.headers.items():
        response.headers[name] = value
    return response


def _alert_record(
    now: str,
    score: float,
    entry: dict[str, Any],
    context: dict[str, str | int],
    destination_port: float,
) -> dict[str, Any]:
    """What is kept in the in-memory alert buffer: no raw features, only a little context."""
    record: dict[str, Any] = {"time": now, "score": round(score, 6)}
    for key in ("category", "attack_techniques"):
        if key in entry:
            record[key] = entry[key]
    record.update(context)
    if destination_port == destination_port:  # not NaN
        record["destination_port"] = int(destination_port)
    return record


def create_app(
    detector: BaseDetector,
    settings: ServiceSettings,
    *,
    model_info: dict[str, Any] | None = None,
    limiter: TokenBucketLimiter | None = None,
    state: ServiceState | None = None,
) -> Flask:
    """Build the application around an already-loaded, calibrated detector."""
    if detector.threshold_ is None:
        raise ValueError("the detector has no calibrated threshold")
    threshold = float(detector.threshold_)
    features = list(detector.feature_names_)
    info: dict[str, Any] = {
        "detector": detector.name,
        "n_features": len(features),
        "threshold": threshold,
        **(model_info or {}),
    }

    app = Flask(__name__, static_folder=None)
    app.config["MAX_CONTENT_LENGTH"] = settings.max_body_bytes
    if settings.trusted_proxies:
        # Only the last N entries of X-Forwarded-For, appended by proxies we operate, are trusted;
        # anything a client puts further left is ignored, so it cannot choose its rate-limit key.
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app, x_for=settings.trusted_proxies
        )
    app.json.sort_keys = False  # type: ignore[attr-defined]
    rate_limiter = limiter or TokenBucketLimiter(settings.rate_limit_per_minute)
    service_state = state or ServiceState(settings.alert_buffer)
    app.extensions["ai_ids_state"] = service_state

    registry = CollectorRegistry()
    requests_total = Counter(
        "ai_ids_requests_total",
        "HTTP requests",
        ["endpoint", "method", "status"],
        registry=registry,
    )
    flows_total = Counter("ai_ids_flows_scored_total", "Flows scored", registry=registry)
    alerts_total = Counter("ai_ids_alerts_total", "Alerts raised", registry=registry)
    scoring_seconds = Histogram(
        "ai_ids_scoring_seconds",
        "Time spent scoring one request",
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5),
        registry=registry,
    )
    Gauge("ai_ids_model_threshold", "Calibrated alert threshold", registry=registry).set(threshold)
    Gauge("ai_ids_model_info", "Loaded model", ["detector"], registry=registry).labels(
        detector=detector.name
    ).set(1)

    def authenticate(scope: str) -> None:
        header = request.headers.get("Authorization", "")
        scheme, _, token = header.partition(" ")
        challenge = {"WWW-Authenticate": "Bearer"}
        if scheme.lower() != "bearer" or not token:
            raise RequestError(401, "unauthorized", "a bearer API key is required", challenge)
        candidate = token.encode()
        is_score = hmac.compare_digest(candidate, settings.api_key.encode())
        is_read = hmac.compare_digest(candidate, settings.read_key.encode())
        allowed = is_score if scope == "score" else (is_score or is_read)
        if not allowed:
            raise RequestError(
                401, "unauthorized", "the API key is not valid for this endpoint", challenge
            )

    def api(scope: str) -> Callable[[F], F]:
        """Rate-limit, then authenticate, an API endpoint."""

        def decorate(view: F) -> F:
            @wraps(view)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                allowed, retry_after = rate_limiter.allow(request.remote_addr or "unknown")
                if not allowed:
                    raise RequestError(
                        429,
                        "rate_limited",
                        "too many requests; retry later",
                        {"Retry-After": str(max(1, int(retry_after) + 1))},
                    )
                authenticate(scope)
                return view(*args, **kwargs)

            return cast(F, wrapper)

        return decorate

    @app.before_request
    def start_request() -> None:
        supplied = request.headers.get("X-Request-ID", "")
        g.request_id = supplied if REQUEST_ID_PATTERN.match(supplied) else uuid.uuid4().hex
        g.started = time.perf_counter()

    @app.after_request
    def finish_request(response: Response) -> Response:
        response.headers["X-Request-ID"] = g.get("request_id", "-")
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
        if not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        if settings.behind_tls or request.is_secure:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        endpoint = request.endpoint or "unmatched"
        requests_total.labels(endpoint, request.method, str(response.status_code)).inc()
        started = g.get("started")
        logger.info(
            "request",
            extra={
                "fields": {
                    "request_id": g.get("request_id"),
                    "method": request.method,
                    "path": request.path,
                    "status": response.status_code,
                    "duration_ms": round((time.perf_counter() - started) * 1000, 2)
                    if started
                    else None,
                    "flows": g.get("n_flows"),
                }
            },
        )
        return response

    @app.errorhandler(RequestError)
    def handle_request_error(error: RequestError) -> Response:
        return _json_error(error)

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> Response:
        code = (error.name or "error").lower().replace(" ", "_")
        return _json_error(RequestError(error.code or 500, code, error.description or error.name))

    @app.errorhandler(Exception)
    def handle_unexpected(error: Exception) -> Response:
        logger.exception("unhandled error", extra={"fields": {"request_id": g.get("request_id")}})
        return _json_error(RequestError(500, "internal_error", "internal server error"))

    # --- public, non-sensitive endpoints ----------------------------------------------------
    @app.get("/healthz")
    def healthz() -> Response:
        return jsonify({"status": "ok"})

    @app.get("/readyz")
    def readyz() -> Response:
        return jsonify({"status": "ready", "detector": detector.name})

    @app.get("/openapi.yaml")
    def openapi() -> Response:
        return send_from_directory(PACKAGE_DIR, "openapi.yaml", mimetype="application/yaml")

    @app.get("/")
    def dashboard() -> Response:
        return send_from_directory(STATIC_DIR, "index.html")

    @app.get("/static/<path:name>")
    def static_files(name: str) -> Response:
        response = send_from_directory(STATIC_DIR, name)
        response.headers["Cache-Control"] = "public, max-age=300"
        return response

    # --- authenticated endpoints --------------------------------------------------------------
    @app.post("/v1/score")
    @api("score")
    def score() -> Response:
        if not request.is_json:
            raise RequestError(
                415, "unsupported_media_type", "Content-Type must be application/json"
            )
        payload = request.get_json(silent=True)
        if payload is None:
            raise RequestError(400, "invalid_json", "the request body is not valid JSON")
        frame, contexts = parse_flows(payload, features, settings)
        g.n_flows = len(frame)

        started = time.perf_counter()
        scores = detector.score(frame)
        flagged = scores > threshold
        categories: dict[int, str] = {}
        predict = getattr(detector, "predict_category", None)
        if predict is not None and flagged.any():
            rows = [i for i in range(len(frame)) if flagged[i]]
            for i, category in zip(rows, predict(frame.iloc[rows]), strict=True):
                if category != "benign":
                    categories[i] = str(category)
        elapsed = time.perf_counter() - started

        results: list[dict[str, Any]] = []
        alerts: list[dict[str, Any]] = []
        now = datetime.now(UTC).isoformat(timespec="seconds")
        ports = (
            frame["destination_port"].to_numpy(dtype=float)
            if "destination_port" in frame.columns
            else None
        )
        for i, value in enumerate(scores):
            entry: dict[str, Any] = {"score": float(value), "alert": bool(flagged[i])}
            if i in categories:
                entry["category"] = categories[i]
                entry["attack_techniques"] = techniques_for_category(categories[i])
            results.append(entry)
            if flagged[i]:
                port = float(ports[i]) if ports is not None else float("nan")
                alerts.append(_alert_record(now, float(value), entry, contexts[i], port))
        service_state.record_batch(len(frame), alerts, elapsed * 1000.0)
        flows_total.inc(len(frame))
        alerts_total.inc(len(alerts))
        scoring_seconds.observe(elapsed)
        return jsonify({"model": info, "threshold": threshold, "results": results})

    @app.get("/v1/alerts")
    @api("read")
    def alerts_endpoint() -> Response:
        try:
            limit = int(request.args.get("limit", "50"))
        except ValueError:
            raise RequestError(422, "invalid_request", "limit must be an integer") from None
        if not 1 <= limit <= MAX_ALERT_LIMIT:
            raise RequestError(
                422, "invalid_request", f"limit must be between 1 and {MAX_ALERT_LIMIT}"
            )
        return jsonify({"alerts": service_state.recent_alerts(limit)})

    @app.get("/v1/stats")
    @api("read")
    def stats() -> Response:
        return jsonify({"model": info, **service_state.snapshot()})

    @app.get("/metrics")
    @api("read")
    def metrics() -> Response:
        return Response(generate_latest(registry), mimetype=CONTENT_TYPE_LATEST)

    return app
