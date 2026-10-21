import json
import logging
import re
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import yaml
from flask import Flask
from flask.testing import FlaskClient

from ai_ids.data.loader import CATEGORY, IS_ATTACK, feature_columns
from ai_ids.data.split import chronological_split
from ai_ids.models.detectors import RandomForestDetector
from ai_ids.registry import IntegrityError, save_detector
from ai_ids.service.app import PACKAGE_DIR, create_app
from ai_ids.service.ratelimit import TokenBucketLimiter
from ai_ids.service.replay import (
    ReplayRateLimitedError,
    build_payload,
    replay_flows,
)
from ai_ids.service.server import build_app, is_loopback, serve
from ai_ids.service.settings import ServiceSettings, SettingsError
from ai_ids.service.state import ServiceState
from ai_ids.service.validation import parse_flows

API_KEY = "score-key-0123456789abcdef"
READ_KEY = "read-key-0123456789abcdef"
SETTINGS = ServiceSettings(api_key=API_KEY, read_key=READ_KEY)
SCORE = {"Authorization": f"Bearer {API_KEY}"}
READ = {"Authorization": f"Bearer {READ_KEY}"}


@pytest.fixture(scope="module")
def prepared(cleaned: pd.DataFrame):  # type: ignore[no-untyped-def]
    split = chronological_split(cleaned)
    features = feature_columns(cleaned)
    detector = RandomForestDetector(n_estimators=20, seed=1).fit(
        split.train[features], split.train[CATEGORY]
    )
    benign = split.val[~split.val[IS_ATTACK]]
    detector.calibrate(detector.score(benign[features]), 0.05)
    detector.set_inference_threads(1)
    return detector, split, features


def make_app(prepared, **overrides) -> Flask:  # type: ignore[no-untyped-def]
    detector, _, _ = prepared
    settings = overrides.pop("settings", SETTINGS)
    return create_app(detector, settings, **overrides)


@pytest.fixture
def client(prepared) -> FlaskClient:  # type: ignore[no-untyped-def]
    return make_app(prepared).test_client()


def payload(prepared, n: int = 25, attacks: bool | None = None) -> dict:  # type: ignore[no-untyped-def]
    _, split, features = prepared
    rows = split.test
    if attacks is not None:
        rows = rows[rows[IS_ATTACK] == attacks]
    return build_payload(rows.head(n), features, SETTINGS.context_fields)


# ---------------------------------------------------------------- settings
def test_settings_from_env_and_validation() -> None:
    env = {"AI_IDS_API_KEY": API_KEY, "AI_IDS_READ_KEY": READ_KEY, "AI_IDS_MAX_FLOWS": "10"}
    settings = ServiceSettings.from_env(env)
    assert settings.max_flows_per_request == 10
    assert settings.behind_tls is False
    assert ServiceSettings.from_env({**env, "AI_IDS_BEHIND_TLS": "true"}).behind_tls is True


@pytest.mark.parametrize(
    ("env", "message"),
    [
        ({}, "missing required"),
        ({"AI_IDS_API_KEY": "short", "AI_IDS_READ_KEY": READ_KEY}, "at least"),
        ({"AI_IDS_API_KEY": API_KEY, "AI_IDS_READ_KEY": API_KEY}, "must differ"),
        (
            {"AI_IDS_API_KEY": API_KEY, "AI_IDS_READ_KEY": READ_KEY, "AI_IDS_MAX_FLOWS": "x"},
            "integer",
        ),
        (
            {"AI_IDS_API_KEY": API_KEY, "AI_IDS_READ_KEY": READ_KEY, "AI_IDS_MAX_FLOWS": "0"},
            "positive",
        ),
    ],
)
def test_settings_reject_unsafe_configuration(env: dict[str, str], message: str) -> None:
    with pytest.raises(SettingsError, match=message) as error:
        ServiceSettings.from_env(env)
    assert API_KEY not in str(error.value)  # secrets never appear in messages


# ---------------------------------------------------------------- rate limiter
def test_token_bucket_allows_burst_then_throttles_then_recovers() -> None:
    now = [0.0]
    limiter = TokenBucketLimiter(60, burst=3, clock=lambda: now[0])
    assert [limiter.allow("a")[0] for _ in range(3)] == [True, True, True]
    allowed, retry = limiter.allow("a")
    assert not allowed
    assert 0.9 < retry <= 1.0
    assert limiter.allow("b")[0]  # other clients are unaffected
    now[0] += 2.0
    assert limiter.allow("a")[0]


def test_token_bucket_prunes_old_keys_and_validates() -> None:
    now = [0.0]
    limiter = TokenBucketLimiter(10, clock=lambda: now[0], max_keys=20)
    for i in range(100):
        now[0] += 0.001
        limiter.allow(f"client-{i}")
    assert len(limiter._buckets) <= 21
    with pytest.raises(ValueError, match="positive"):
        TokenBucketLimiter(0)


# ---------------------------------------------------------------- validation
def test_validation_accepts_nulls_and_context(prepared) -> None:  # type: ignore[no-untyped-def]
    _, _, features = prepared
    body = payload(prepared, 3)
    body["flows"][0][features[0]] = None
    frame, contexts = parse_flows(body, features, SETTINGS)
    assert frame.shape == (3, len(features))
    assert np.isnan(frame.iloc[0, 0])
    assert "source_ip" in contexts[0]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: {"flows": b["flows"], "extra": 1},
        lambda b: {"flows": []},
        lambda b: {"flows": "nope"},
        lambda b: [b],
        lambda b: {"flows": [1, 2]},
        lambda b: {"flows": [{**b["flows"][0], "surprise": 1}]},
        lambda b: {"flows": [{k: v for k, v in b["flows"][0].items() if k != "flow_duration"}]},
        lambda b: {"flows": [{**b["flows"][0], "flow_duration": "12"}]},
        lambda b: {"flows": [{**b["flows"][0], "flow_duration": True}]},
        lambda b: {"flows": [{**b["flows"][0], "flow_duration": float("inf")}]},
        lambda b: {"flows": [{**b["flows"][0], "flow_duration": float("nan")}]},
        lambda b: {"flows": [{**b["flows"][0], "flow_duration": 1e30}]},
        lambda b: {"flows": [{**b["flows"][0], "source_ip": "x" * 200}]},
        lambda b: {"flows": [{**b["flows"][0], "source_ip": "bad\nline"}]},
        lambda b: {"flows": [{**b["flows"][0], "source_ip": ["list"]}]},
    ],
)
def test_validation_rejects_malformed_input(prepared, mutate) -> None:  # type: ignore[no-untyped-def]
    _, _, features = prepared
    with pytest.raises(Exception, match=r"."):
        parse_flows(mutate(payload(prepared, 1)), features, SETTINGS)


def test_validation_limits_batch_size(prepared) -> None:  # type: ignore[no-untyped-def]
    _, _, features = prepared
    small = ServiceSettings(api_key=API_KEY, read_key=READ_KEY, max_flows_per_request=2)
    with pytest.raises(Exception, match="at most 2"):
        parse_flows(payload(prepared, 3), features, small)


# ---------------------------------------------------------------- state
def test_state_bounds_and_percentiles() -> None:
    now = [1_000_000.0]
    state = ServiceState(alert_buffer=3, clock=lambda: now[0])
    for i in range(5):
        state.record_batch(10, [{"n": i}], latency_ms=float(i + 1))
    assert [a["n"] for a in state.recent_alerts(10)] == [4, 3, 2]  # bounded, newest first
    snapshot = state.snapshot()
    assert snapshot["flows_scored"] == 50
    assert snapshot["alerts_raised"] == 5
    assert snapshot["alerts_buffered"] == 3
    assert snapshot["request_latency_ms"]["p50"] == pytest.approx(3.0)
    assert snapshot["series"][-1] == {"flows": 50, "alerts": 5}
    assert snapshot["bucket_seconds"] == 5
    assert len(snapshot["series"]) == 120
    now[0] += 5
    state.record_batch(7, [{"n": 9}], 1.0)
    later = state.snapshot()["series"]
    assert later[-1] == {"flows": 7, "alerts": 1}
    assert later[-2] == {"flows": 50, "alerts": 5}
    now[0] += 3600
    state.record_batch(1, [], 1.0)
    assert state.snapshot()["series"][-1] == {"flows": 1, "alerts": 0}
    assert sum(p["flows"] for p in state.snapshot()["series"]) == 1  # old buckets expired


# ---------------------------------------------------------------- app: public endpoints
def test_probes_are_public_and_carry_security_headers(client: FlaskClient) -> None:
    for path in ("/healthz", "/readyz", "/openapi.yaml", "/"):
        response = client.get(path)
        assert response.status_code == 200, path
        assert "default-src 'none'" in response.headers["Content-Security-Policy"]
        assert response.headers["X-Content-Type-Options"] == "nosniff"
        assert response.headers["X-Frame-Options"] == "DENY"
        assert response.headers["Referrer-Policy"] == "no-referrer"
        assert "Strict-Transport-Security" not in response.headers
    assert client.get("/healthz").headers["Cache-Control"] == "no-store"
    assert client.get("/static/dashboard.js").headers["Cache-Control"].startswith("public")


def test_hsts_only_when_behind_tls(prepared) -> None:  # type: ignore[no-untyped-def]
    tls = ServiceSettings(api_key=API_KEY, read_key=READ_KEY, behind_tls=True)
    response = make_app(prepared, settings=tls).test_client().get("/healthz")
    assert "max-age=31536000" in response.headers["Strict-Transport-Security"]


def test_unknown_routes_and_methods_return_json_errors(client: FlaskClient) -> None:
    missing = client.get("/nope")
    assert missing.status_code == 404
    assert missing.get_json()["error"]["code"] == "not_found"
    wrong_method = client.get("/v1/score", headers=SCORE)
    assert wrong_method.status_code == 405
    assert "traceback" not in wrong_method.get_data(as_text=True).lower()


def test_request_id_is_echoed_only_when_well_formed(client: FlaskClient) -> None:
    good = client.get("/healthz", headers={"X-Request-ID": "abc-12345678"})
    assert good.headers["X-Request-ID"] == "abc-12345678"
    for malformed in ("short", "has spaces in it!", "x" * 200, "semi;colon-1234567"):
        replaced = client.get("/healthz", headers={"X-Request-ID": malformed})
        assert re.fullmatch(r"[0-9a-f]{32}", replaced.headers["X-Request-ID"]), malformed


# ---------------------------------------------------------------- app: authentication
@pytest.mark.parametrize("path", ["/v1/alerts", "/v1/stats", "/metrics"])
def test_read_endpoints_need_a_key(client: FlaskClient, path: str) -> None:
    assert client.get(path).status_code == 401
    assert (
        client.get(path, headers={"Authorization": "Bearer wrong-key-000000000000"}).status_code
        == 401
    )
    assert client.get(path, headers={"Authorization": f"Basic {READ_KEY}"}).status_code == 401
    for headers in (READ, SCORE):
        assert client.get(path, headers=headers).status_code == 200
    challenge = client.get(path).headers["WWW-Authenticate"]
    assert challenge == "Bearer"


def test_read_key_cannot_score_but_score_key_can(client: FlaskClient, prepared) -> None:  # type: ignore[no-untyped-def]
    body = payload(prepared, 3)
    assert client.post("/v1/score", json=body).status_code == 401
    assert client.post("/v1/score", json=body, headers=READ).status_code == 401
    assert client.post("/v1/score", json=body, headers=SCORE).status_code == 200


# ---------------------------------------------------------------- app: scoring
def test_scores_match_the_detector_and_alerts_follow_the_threshold(  # type: ignore[no-untyped-def]
    client: FlaskClient, prepared
) -> None:
    detector, split, features = prepared
    rows = split.test.head(60)
    response = client.post(
        "/v1/score",
        json=build_payload(rows, features, SETTINGS.context_fields),
        headers=SCORE,
    )
    assert response.status_code == 200
    body = response.get_json()
    expected = detector.score(rows[features])
    got = np.array([r["score"] for r in body["results"]])
    np.testing.assert_allclose(got, expected, rtol=1e-9)
    assert [r["alert"] for r in body["results"]] == list(expected > detector.threshold_)
    assert body["threshold"] == pytest.approx(detector.threshold_)
    assert body["model"]["detector"] == "random_forest"


def test_alerts_carry_context_and_techniques_but_not_raw_features(  # type: ignore[no-untyped-def]
    client: FlaskClient, prepared
) -> None:
    body = payload(prepared, 400, attacks=True)
    result = client.post("/v1/score", json=body, headers=SCORE).get_json()
    flagged = [r for r in result["results"] if r["alert"]]
    assert flagged, "expected the synthetic attacks to raise alerts"
    categorised = [r for r in flagged if "category" in r]
    assert categorised
    assert all(r["attack_techniques"] for r in categorised)
    alerts = client.get("/v1/alerts?limit=5", headers=READ).get_json()["alerts"]
    assert alerts
    assert {"time", "score", "source_ip"} <= set(alerts[0])
    assert "flow_duration" not in alerts[0]  # raw features are never stored


def test_malformed_requests_get_precise_errors_without_echoing_values(  # type: ignore[no-untyped-def]
    client: FlaskClient, prepared
) -> None:
    body = payload(prepared, 2)
    body["flows"][0]["flow_duration"] = "SECRET-VALUE-123"
    response = client.post("/v1/score", json=body, headers=SCORE)
    assert response.status_code == 422
    assert "SECRET-VALUE-123" not in response.get_data(as_text=True)
    assert response.get_json()["error"]["code"] == "invalid_request"

    not_json = client.post("/v1/score", data="a=b", headers={**SCORE, "Content-Type": "text/plain"})
    assert not_json.status_code == 415
    broken = client.post(
        "/v1/score", data="{not json", headers={**SCORE, "Content-Type": "application/json"}
    )
    assert broken.status_code == 400


def test_body_and_batch_limits(prepared) -> None:  # type: ignore[no-untyped-def]
    small = ServiceSettings(
        api_key=API_KEY, read_key=READ_KEY, max_body_bytes=2000, max_flows_per_request=2
    )
    client = make_app(prepared, settings=small).test_client()
    assert client.post("/v1/score", json=payload(prepared, 50), headers=SCORE).status_code == 413
    roomy = ServiceSettings(api_key=API_KEY, read_key=READ_KEY, max_flows_per_request=2)
    client = make_app(prepared, settings=roomy).test_client()
    too_many = client.post("/v1/score", json=payload(prepared, 5), headers=SCORE)
    assert too_many.status_code == 422


def test_rate_limiting_returns_429_with_retry_after(prepared) -> None:  # type: ignore[no-untyped-def]
    now = [0.0]
    limiter = TokenBucketLimiter(60, burst=2, clock=lambda: now[0])
    client = make_app(prepared, limiter=limiter).test_client()
    assert client.get("/v1/stats", headers=READ).status_code == 200
    assert client.get("/v1/stats", headers=READ).status_code == 200
    throttled = client.get("/v1/stats", headers=READ)
    assert throttled.status_code == 429
    assert int(throttled.headers["Retry-After"]) >= 1
    assert client.get("/healthz").status_code == 200  # probes are not rate limited
    # failed authentication is rate limited too, which slows key guessing
    for _ in range(5):
        client.get("/v1/stats", headers={"Authorization": "Bearer guess-000000000000000"})
    assert (
        client.get(
            "/v1/stats", headers={"Authorization": "Bearer guess-000000000000000"}
        ).status_code
        == 429
    )


def test_trusted_proxy_count_sets_the_rate_limit_key(prepared) -> None:  # type: ignore[no-untyped-def]
    now = [0.0]
    settings = ServiceSettings(api_key=API_KEY, read_key=READ_KEY, trusted_proxies=1)
    limiter = TokenBucketLimiter(60, burst=1, clock=lambda: now[0])
    client = make_app(prepared, settings=settings, limiter=limiter).test_client()

    def get(forwarded: str) -> int:
        headers = {**READ, "X-Forwarded-For": forwarded}
        return client.get("/v1/stats", headers=headers).status_code

    # the proxy-appended (rightmost) address is the key; leftmost entries are client-controlled
    assert get("203.0.113.1, 198.51.100.7") == 200
    assert get("203.0.113.99, 198.51.100.7") == 429  # spoofing the left entry does not help
    assert get("203.0.113.1, 198.51.100.8") == 200  # a different real client has its own bucket


def test_forwarded_headers_are_ignored_without_trusted_proxies(prepared) -> None:  # type: ignore[no-untyped-def]
    now = [0.0]
    limiter = TokenBucketLimiter(60, burst=1, clock=lambda: now[0])
    client = make_app(prepared, limiter=limiter).test_client()
    first = {**READ, "X-Forwarded-For": "1.1.1.1"}
    second = {**READ, "X-Forwarded-For": "2.2.2.2"}
    assert client.get("/v1/stats", headers=first).status_code == 200
    assert client.get("/v1/stats", headers=second).status_code == 429


def test_trusted_proxies_setting_is_validated() -> None:
    base = {"AI_IDS_API_KEY": API_KEY, "AI_IDS_READ_KEY": READ_KEY}
    assert ServiceSettings.from_env({**base, "AI_IDS_TRUSTED_PROXIES": "2"}).trusted_proxies == 2
    for bad in ("x", "-1", "9"):
        with pytest.raises(SettingsError, match=r"trusted_proxies|AI_IDS_TRUSTED_PROXIES"):
            ServiceSettings.from_env({**base, "AI_IDS_TRUSTED_PROXIES": bad})


def test_alerts_limit_validation(client: FlaskClient) -> None:
    assert client.get("/v1/alerts?limit=abc", headers=READ).status_code == 422
    assert client.get("/v1/alerts?limit=0", headers=READ).status_code == 422
    assert client.get("/v1/alerts?limit=201", headers=READ).status_code == 422


def test_metrics_reflect_scoring(client: FlaskClient, prepared) -> None:  # type: ignore[no-untyped-def]
    client.post("/v1/score", json=payload(prepared, 10), headers=SCORE)
    text = client.get("/metrics", headers=READ).get_data(as_text=True)
    assert "ai_ids_flows_scored_total 10.0" in text
    assert 'ai_ids_requests_total{endpoint="score",method="POST",status="200"} 1.0' in text
    assert "ai_ids_scoring_seconds_bucket" in text
    assert 'ai_ids_model_info{detector="random_forest"} 1.0' in text


def test_unexpected_errors_do_not_leak_details(prepared) -> None:  # type: ignore[no-untyped-def]
    detector, _, _ = prepared

    class Exploding(RandomForestDetector):
        def score(self, X: pd.DataFrame) -> np.ndarray:  # type: ignore[override]
            raise RuntimeError("internal-secret-path /etc/shadow")

    broken = Exploding()
    broken.feature_names_ = detector.feature_names_
    broken.threshold_ = detector.threshold_
    app = create_app(broken, SETTINGS)
    app.config["PROPAGATE_EXCEPTIONS"] = False
    response = app.test_client().post("/v1/score", json=payload(prepared, 2), headers=SCORE)
    assert response.status_code == 500
    assert "shadow" not in response.get_data(as_text=True)
    assert response.get_json()["error"]["code"] == "internal_error"


def test_logs_never_contain_keys_or_payloads(client: FlaskClient, prepared, caplog) -> None:  # type: ignore[no-untyped-def]
    caplog.set_level(logging.INFO, logger="ai_ids.service")
    body = payload(prepared, 5)
    client.post("/v1/score", json=body, headers=SCORE)
    client.get("/v1/stats", headers=READ)
    logged = " ".join(
        json.dumps(getattr(record, "fields", {}), default=str) + record.getMessage()
        for record in caplog.records
    )
    assert logged
    assert API_KEY not in logged
    assert READ_KEY not in logged
    assert body["flows"][0]["source_ip"] not in logged
    assert '"flows": 5' in logged


def test_app_requires_a_calibrated_detector() -> None:
    with pytest.raises(ValueError, match="threshold"):
        create_app(RandomForestDetector(), SETTINGS)


# ---------------------------------------------------------------- dashboard and spec
def test_dashboard_is_csp_clean_and_never_uses_inner_html() -> None:
    static = PACKAGE_DIR / "static"
    html = (static / "index.html").read_text()
    script = (static / "dashboard.js").read_text()
    assert '<script src="/static/dashboard.js">' in html
    assert not re.search(r"<script(?![^>]*\bsrc=)", html)  # no inline scripts
    assert not re.search(r"\son[a-z]+\s*=", html, re.IGNORECASE)  # no inline event handlers
    assert not re.search(r"\sstyle\s*=", html, re.IGNORECASE)  # no inline styles (blocked by CSP)
    assert "javascript:" not in html.lower()
    assert "innerHTML" not in script
    assert "eval(" not in script
    assert "document.write" not in script
    assert "textContent" in script


def test_openapi_spec_matches_the_registered_routes(client: FlaskClient) -> None:
    spec = yaml.safe_load((PACKAGE_DIR / "openapi.yaml").read_text())
    documented = {(path, method.upper()) for path, item in spec["paths"].items() for method in item}
    registered = {
        (rule.rule, method)
        for rule in client.application.url_map.iter_rules()
        for method in rule.methods - {"HEAD", "OPTIONS"}
        if rule.rule not in {"/", "/static/<path:name>"}
    }
    assert documented == registered
    for path, item in spec["paths"].items():
        for method, operation in item.items():
            secured = operation.get("security", spec["security"]) != []
            requires_key = (path, method.upper()) in {
                ("/v1/score", "POST"),
                ("/v1/alerts", "GET"),
                ("/v1/stats", "GET"),
                ("/metrics", "GET"),
            }
            assert secured == requires_key, (path, method)


# ---------------------------------------------------------------- server
def test_loopback_detection_and_remote_binding_guard(prepared) -> None:  # type: ignore[no-untyped-def]
    for host in ("127.0.0.1", "::1", "localhost"):
        assert is_loopback(host)
    for host in ("0.0.0.0", "192.168.1.5"):
        assert not is_loopback(host)
    with pytest.raises(SystemExit, match="refusing to bind"):
        serve(make_app(prepared), "0.0.0.0", 8080, allow_remote=False)


def test_build_app_verifies_the_artifact(prepared, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    detector, _, _ = prepared
    save_detector(detector, tmp_path, hmac_key=b"k" * 32)
    app = build_app(tmp_path, SETTINGS, hmac_key=b"k" * 32)
    ready = app.test_client().get("/readyz")
    assert ready.get_json()["status"] == "ready"
    stats = app.test_client().get("/v1/stats", headers=READ).get_json()
    assert stats["model"]["signed"] is True
    assert len(stats["model"]["artifact_sha256"]) == 64
    with pytest.raises(IntegrityError):
        build_app(tmp_path, SETTINGS, hmac_key=b"wrong-key-wrong-key-wrong-key!!")
    (tmp_path / "model.joblib").write_bytes(b"tampered")
    with pytest.raises(IntegrityError):
        build_app(tmp_path, SETTINGS, hmac_key=b"k" * 32)


# ---------------------------------------------------------------- replay
def test_replay_through_the_app_matches_ground_truth(prepared) -> None:  # type: ignore[no-untyped-def]
    detector, split, features = prepared
    app = make_app(prepared)
    client = app.test_client()

    def post(url: str, headers: dict[str, str], body: bytes) -> dict:  # type: ignore[type-arg]
        assert url.endswith("/v1/score")
        response = client.post("/v1/score", data=body, headers=headers)
        assert response.status_code == 200
        return response.get_json()

    sleeps: list[float] = []
    frame = split.test.sample(400, random_state=0)  # includes attacks and benign flows
    assert frame[IS_ATTACK].any()
    assert (~frame[IS_ATTACK]).any()
    summary = replay_flows(
        frame, features, base_url="http://x", api_key=API_KEY, speed=60, batch_size=50,
        sleep=sleeps.append, post=post,
    )  # fmt: skip
    expected_alerts = detector.score(frame[features]) > detector.threshold_
    truth = frame[IS_ATTACK].to_numpy()
    assert summary.flows_sent == 400
    assert summary.batches == 8
    json.dumps(summary.to_dict())  # every count must be a plain, serialisable number
    assert all(type(v) in (int, float, type(None)) for v in summary.to_dict().values())
    assert summary.alerts == int(expected_alerts.sum())
    assert summary.true_positives == int((expected_alerts & truth).sum())
    assert summary.false_positives == int((expected_alerts & ~truth).sum())
    assert summary.attacks_sent == int(truth.sum())
    assert summary.recall == pytest.approx((expected_alerts & truth).sum() / truth.sum())
    assert all(0.0 <= s <= 2.0 for s in sleeps)
    stats = client.get("/v1/stats", headers=READ).get_json()
    assert stats["flows_scored"] == 400


def test_replay_retries_when_rate_limited_and_validates(prepared) -> None:  # type: ignore[no-untyped-def]
    _, split, features = prepared
    frame = split.test.head(10)
    calls = {"n": 0}
    waits: list[float] = []

    def post(url: str, headers: dict[str, str], body: bytes) -> dict:  # type: ignore[type-arg]
        calls["n"] += 1
        if calls["n"] == 1:
            raise ReplayRateLimitedError(3.0)
        return {"results": [{"alert": False}] * 10}

    summary = replay_flows(
        frame, features, base_url="http://x", api_key=API_KEY, batch_size=10,
        sleep=waits.append, post=post,
    )  # fmt: skip
    assert summary.flows_sent == 10
    assert waits == [3.0]
    with pytest.raises(ValueError, match="positive"):
        replay_flows(frame, features, base_url="http://x", api_key=API_KEY, speed=0)

    def always_limited(url: str, headers: dict[str, str], body: bytes) -> dict:  # type: ignore[type-arg]
        raise ReplayRateLimitedError(0.0)

    with pytest.raises(ReplayRateLimitedError):
        replay_flows(
            frame, features, base_url="http://x", api_key=API_KEY, sleep=lambda s: None,
            post=always_limited,
        )  # fmt: skip


def test_build_payload_is_json_safe(prepared) -> None:  # type: ignore[no-untyped-def]
    _, split, features = prepared
    rows = split.test.head(3).copy()
    rows.iloc[0, rows.columns.get_loc(features[0])] = np.nan
    text = json.dumps(build_payload(rows, features, SETTINGS.context_fields), allow_nan=False)
    assert '"source_ip"' in text
    parsed = json.loads(text)
    assert parsed["flows"][0][features[0]] is None
    assert isinstance(parsed["flows"][0]["timestamp"], str)


# ---------------------------------------------------------------- end to end over real HTTP
@pytest.fixture
def live_server(prepared):  # type: ignore[no-untyped-def]
    """The real service under waitress on an ephemeral loopback port."""
    import threading

    from waitress import create_server

    server = create_server(make_app(prepared), host="127.0.0.1", port=0, ident="ai-ids")
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.effective_port}"
    server.close()
    thread.join(timeout=5)


def test_replay_command_over_real_http(live_server: str, monkeypatch, capsys) -> None:  # type: ignore[no-untyped-def]
    from ai_ids.cli import main

    monkeypatch.setenv("AI_IDS_API_KEY", API_KEY)
    code = main(
        ["replay", "--synthetic", "--url", live_server, "--speed", "100000", "--limit", "120"]
    )
    assert code == 0
    summary = json.loads(capsys.readouterr().out.split("\n", 1)[1])
    assert summary["flows_sent"] == 120
    assert summary["batches"] == 3
    import urllib.request

    request = urllib.request.Request(live_server + "/v1/stats", headers=READ)
    with urllib.request.urlopen(request, timeout=5) as response:
        stats = json.loads(response.read())
    assert stats["flows_scored"] == 120
    assert stats["alerts_raised"] == summary["alerts"]


def test_http_post_error_handling(live_server: str) -> None:
    import urllib.error

    from ai_ids.service.replay import http_post

    with pytest.raises(urllib.error.HTTPError) as unauthorized:
        http_post(live_server + "/v1/score", {"Authorization": "Bearer nope-0000000000000"}, b"{}")
    assert unauthorized.value.code == 401
    with pytest.raises(ValueError, match="http"):
        http_post("file:///etc/passwd", {}, b"{}")


def test_replay_rate_limit_is_translated_for_the_client(prepared) -> None:  # type: ignore[no-untyped-def]
    import threading

    from waitress import create_server

    now = [0.0]
    limiter = TokenBucketLimiter(60, burst=1, clock=lambda: now[0])
    server = create_server(make_app(prepared, limiter=limiter), host="127.0.0.1", port=0)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        from ai_ids.service.replay import http_post

        url = f"http://127.0.0.1:{server.effective_port}/v1/stats"
        assert http_post.__name__ == "http_post"
        import urllib.error
        import urllib.request

        def get() -> int:
            request = urllib.request.Request(url, headers=READ)
            try:
                with urllib.request.urlopen(request, timeout=5) as response:
                    return int(response.status)
            except urllib.error.HTTPError as error:
                return int(error.code)

        assert get() == 200
        assert get() == 429
    finally:
        server.close()
        thread.join(timeout=5)


# ---------------------------------------------------------------- CLI configuration paths
def test_serve_and_replay_report_configuration_errors(monkeypatch, capsys, tmp_path) -> None:  # type: ignore[no-untyped-def]
    from ai_ids.cli import main

    monkeypatch.delenv("AI_IDS_API_KEY", raising=False)
    monkeypatch.delenv("AI_IDS_READ_KEY", raising=False)
    assert main(["serve", "--model-dir", str(tmp_path)]) == 2
    assert "AI_IDS_API_KEY" in capsys.readouterr().err
    assert main(["replay", "--synthetic"]) == 2
    assert "AI_IDS_API_KEY" in capsys.readouterr().err


def test_serve_demo_prints_throwaway_keys_and_serves(  # type: ignore[no-untyped-def]
    prepared, tmp_path, monkeypatch, capsys
) -> None:
    from ai_ids import cli

    detector, _, _ = prepared
    save_detector(detector, tmp_path)
    started: dict[str, object] = {}
    monkeypatch.setattr(
        cli,
        "serve",
        lambda app, host, port, allow_remote: started.update(
            app=app, host=host, port=port, remote=allow_remote
        ),
    )
    assert cli.main(["serve", "--model-dir", str(tmp_path), "--demo", "--port", "9099"]) == 0
    output = capsys.readouterr().out
    match = re.search(r"#key=([\w-]+)", output)
    assert match
    app = started["app"]
    assert isinstance(app, Flask)
    assert started["host"] == "127.0.0.1"
    assert started["remote"] is False
    read_key = match.group(1)
    assert (
        app.test_client()
        .get("/v1/stats", headers={"Authorization": f"Bearer {read_key}"})
        .status_code
        == 200
    )
    # the demo keys are random per start
    assert cli.main(["serve", "--model-dir", str(tmp_path), "--demo"]) == 0
    assert match.group(1) not in capsys.readouterr().out


def test_replay_selection_is_in_capture_time_order(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """--limit must take the earliest flows in time, not the first rows of the grouped split."""
    import argparse

    from ai_ids.cli import _replay_frame
    from ai_ids.config import TrainConfig

    args = argparse.Namespace(
        synthetic=True, data=None, start=None, minutes=None, limit=600, config=None
    )
    frame, _ = _replay_frame(args, TrainConfig())
    assert frame["timestamp"].is_monotonic_increasing
    assert frame["is_attack"].any(), "a time-ordered window must contain attacks, not one class"
    assert (~frame["is_attack"]).any()


def test_fixed_rate_replay_paces_evenly_and_validates(prepared) -> None:  # type: ignore[no-untyped-def]
    _, split, features = prepared
    frame = split.test.head(200)
    sleeps: list[float] = []

    def post(url: str, headers: dict[str, str], body: bytes) -> dict:  # type: ignore[type-arg]
        return {"results": [{"alert": False}] * len(json.loads(body)["flows"])}

    summary = replay_flows(
        frame, features, base_url="http://x", api_key=API_KEY, rate=100.0, batch_size=50,
        sleep=sleeps.append, post=post,
    )  # fmt: skip
    assert summary.flows_sent == 200
    assert sleeps == [0.5, 0.5, 0.5]  # 50 flows at 100 flows/s, between each of 4 batches
    with pytest.raises(ValueError, match="positive"):
        replay_flows(frame, features, base_url="http://x", api_key=API_KEY, rate=0.0)
