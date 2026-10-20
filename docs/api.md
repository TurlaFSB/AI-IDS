# API reference

The machine-readable contract is the OpenAPI 3.0 document at `src/ai_ids/service/openapi.yaml`,
served by a running instance at `/openapi.yaml`. This page is the human summary.

## Authentication

Send `Authorization: Bearer <key>`. There are two keys, both supplied through the environment
(`AI_IDS_API_KEY`, `AI_IDS_READ_KEY`), at least 16 characters, and different from each other.

| Endpoint | Method | Key required |
|---|---|---|
| `/v1/score` | POST | score key |
| `/v1/alerts`, `/v1/stats`, `/metrics` | GET | read key or score key |
| `/healthz`, `/readyz`, `/openapi.yaml`, `/`, `/static/*` | GET | none |

A missing or wrong key returns `401` with `WWW-Authenticate: Bearer`. The body never says which
key was wrong.

## `POST /v1/score`

Request body: a JSON object with exactly one key, `flows`, a non-empty list (at most
`AI_IDS_MAX_FLOWS`, default 1000). Each flow is an object that contains **every** model feature as
a finite number or `null` (missing). Optional context fields, kept with alerts, are `flow_id`,
`source_ip`, `destination_ip`, `source_port` and `timestamp` (strings of at most 64 printable
characters, or integers). Any other field is rejected.

```json
{"flows": [{"destination_port": 443, "flow_duration": 120000, "...": 0,
            "source_ip": "192.0.2.10", "timestamp": "2017-07-05 10:15:00"}]}
```

Response `200`:

```json
{"model": {"detector": "random_forest_aug", "n_features": 78, "threshold": 0.31,
           "artifact_sha256": "...", "trained_at": "...", "signed": true},
 "threshold": 0.31,
 "results": [{"score": 0.02, "alert": false},
             {"score": 0.97, "alert": true, "category": "dos", "attack_techniques": ["T1499"]}]}
```

`alert` is `score > threshold`. `category` and `attack_techniques` appear only on alerts, and only
for detectors that can name a category (the supervised ones); the technique mapping is analyst
assigned and approximate (`docs/compliance.md`).

## `GET /v1/alerts?limit=N`

Most recent alerts first, `1 <= N <= 200` (default 50), from an in-memory buffer of
`AI_IDS_ALERT_BUFFER` entries (default 500). Entries hold the time, score, category, ATT&CK
techniques and the context fields that were supplied. Raw features are not stored.

## `GET /v1/stats`

Model information, uptime, counters, a ten-minute series of five-second buckets and request
latency percentiles (p50/p95/p99) over the last 2000 requests. These are per-request service
timings on the host running the service, not a benchmark.

## `GET /metrics`

Prometheus text format: `ai_ids_requests_total{endpoint,method,status}`,
`ai_ids_flows_scored_total`, `ai_ids_alerts_total`, `ai_ids_scoring_seconds` (histogram),
`ai_ids_model_threshold` and `ai_ids_model_info{detector}`. The endpoint requires the read key;
configure the scraper with a bearer token.

## Errors

All errors are JSON: `{"error": {"code": "...", "message": "..."}}`. Messages name fields and
positions and never repeat client-supplied values.

| Status | Code | Meaning |
|---|---|---|
| 400 | `invalid_json` | body is not valid JSON |
| 401 | `unauthorized` | missing or invalid key for the endpoint |
| 413 | `request_entity_too_large` | body exceeds `max_body_bytes` (5,000,000) |
| 415 | `unsupported_media_type` | `Content-Type` is not `application/json` |
| 422 | `invalid_request` | schema, range or size violation |
| 429 | `rate_limited` | rate limit exceeded; honour `Retry-After` |
| 500 | `internal_error` | unexpected failure; details only in the server log |

Every response carries an `X-Request-ID` (a well-formed client value of 8-64 characters
`[A-Za-z0-9-]` is echoed, otherwise one is generated) that also appears in the structured log.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `AI_IDS_API_KEY` | required | score key |
| `AI_IDS_READ_KEY` | required | read key |
| `AI_IDS_MAX_FLOWS` | 1000 | flows per request |
| `AI_IDS_RATE_LIMIT_PER_MINUTE` | 120 | per-client-address rate limit |
| `AI_IDS_ALERT_BUFFER` | 500 | in-memory alerts kept |
| `AI_IDS_BEHIND_TLS` | unset | send HSTS when `1`, `true` or `yes` |
| `AI_IDS_MODEL_HMAC_KEY` | unset | verify the model manifest signature |
