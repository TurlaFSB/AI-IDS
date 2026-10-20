# Runbook: scoring service

Audience: whoever operates `ai-ids serve`. Read `docs/threat-model.md` first.

## Prerequisites

- A model directory produced by `ai-ids train`, stored on a controlled path. Artifacts are
  pickle-based: only serve models you trained and stored yourself, and sign them
  (`AI_IDS_MODEL_HMAC_KEY` at train and serve time).
- Two distinct random keys: `python -c "import secrets; print(secrets.token_urlsafe(32))"`.
  Supply them as environment variables from a secret store, never on a command line or in the repo.
- A TLS-terminating reverse proxy if anything other than the local host will connect.

## Start

```bash
export AI_IDS_API_KEY=...   AI_IDS_READ_KEY=...   # from your secret store
export AI_IDS_MODEL_HMAC_KEY=...                   # if the model was signed
ai-ids serve --model-dir models/<run>/<detector> --host 127.0.0.1 --port 8080
```

Startup exits with code 2 and a message on missing or weak keys. A model whose digest or
signature does not match raises an integrity error and the service does not start. Binding beyond loopback requires `--allow-remote`, which you should pass
only with a TLS proxy in front. Set `AI_IDS_BEHIND_TLS=1` behind that proxy to send HSTS.

Local demonstration with throwaway keys and synthetic data:

```bash
ai-ids synth --out data/synthetic.csv && ai-ids train --data data/synthetic.csv --out models/demo --config configs/light.yaml
ai-ids serve --model-dir models/demo/random_forest --demo        # prints the dashboard URL and keys
AI_IDS_API_KEY=<printed> ai-ids replay --synthetic --rate 20     # in a second terminal
```

## Reverse proxy requirements

- Terminate TLS 1.2+ (prefer 1.3) and forward to `127.0.0.1:8080`.
- Enforce per-client rate limits and connection limits at the proxy. The service limits by peer
  address, and behind a proxy that address is the proxy's, so all clients share one bucket. Either
  leave the proxy's own limits as the real control, or raise `AI_IDS_RATE_LIMIT_PER_MINUTE` to
  suit the aggregate load.
- Do not expose `/metrics` publicly; it needs the read key but should also be network-restricted.

## Health and monitoring

| Probe | Use |
|---|---|
| `GET /healthz` | liveness: the process answers |
| `GET /readyz` | readiness: a calibrated model is loaded |
| `GET /metrics` | Prometheus scrape (bearer read key) |

Suggested alerts: sustained 5xx rate, `ai_ids_scoring_seconds` p95 rising, a sudden change in
`ai_ids_alerts_total / ai_ids_flows_scored_total` (a drop can mean a blinded detector or broken
feed; a surge can mean an attack or drift), and 429 rate.

## Logs

One JSON line per request with request ID, method, path, status, duration and flow count. Keys,
request bodies, feature values and addresses are not logged. Logs go to stderr; ship them with the
platform's collector and apply your retention policy (`docs/data-governance.md`).

## Common problems

| Symptom | Cause and action |
|---|---|
| Exit 2 at start | missing or short key, or keys equal; fix the environment |
| Integrity error at start | model digest or signature mismatch: treat as a possible tamper, do not bypass; retrain or restore from a trusted copy |
| `401` | wrong key for the endpoint (reading with a read key is fine, scoring needs the score key) |
| `422` mentioning missing features | client must send every model feature; fetch the list from the model report |
| `429` | slow the client or raise the limit; honour `Retry-After` |
| Alerts vanish after restart | by design: alerts are in memory only |
| Dashboard shows no data | open it with `#key=<read key>`, or paste the key into the prompt |

## Key rotation

Change the environment values and restart. Because state is in memory, a restart clears the alert
buffer and counters; export what you need first. There is no key-expiry or per-client key
management; for multiple tenants, put an authenticating gateway in front.

## Model update and rollback

Train and evaluate the candidate offline, compare it with the incumbent on held-out data, then
start the new instance on the new directory and switch the proxy. Keep the previous model
directory (with its manifest) so rollback is switching back. Automated promotion gates are on the
roadmap and are not implemented.

## Data handling

Alerts can contain IP addresses (personal data). They live in memory, are bounded by
`AI_IDS_ALERT_BUFFER` and are never persisted by the service. Restrict dashboard and API access
accordingly, and do not forward real traffic to a demo instance.
