# 0010. Scoring service, dashboard and replay demo

Status: Accepted (2026-10-20)

## Context
A detector that can only be run as a batch job is hard to evaluate operationally and hard to
demonstrate. The service has to accept hostile input from the network, so it is the first part of
the project inside a real trust boundary (threat model, T5 and T8). It needs a reviewable security
design, not just endpoints.

## Decision
- **Stack.** A Flask application factory (`create_app`) served by waitress. Flask keeps the surface
  small and auditable; waitress is a pure-Python production WSGI server that also runs on Windows,
  where the project is developed. Metrics use `prometheus_client` with a private registry.
- **Model loading.** Only through `registry.load_detector`, so the SHA-256 digest (and HMAC
  signature, when a key is configured) is verified before the pickle is read. The service refuses
  a detector without a calibrated threshold.
- **Authentication and authorisation.** Two bearer keys from the environment, minimum 16
  characters, compared with `hmac.compare_digest`. The score key is required to submit flows. The
  read key (or the score key) reads alerts, statistics and metrics. Keys are never logged and never
  appear in error bodies.
- **Input validation.** The body must be a JSON object with exactly one key, `flows`; the batch
  size and body size are capped; every feature must be a finite number or null; context fields are
  length- and character-restricted. Error messages name positions and fields, never client values.
- **Abuse resistance.** A token-bucket rate limiter per client address runs before authentication,
  so unauthenticated floods are throttled too. Request size, batch size and buffer sizes are bounded.
- **Transport and headers.** The service has no TLS of its own. `serve` refuses to bind beyond
  loopback unless `--allow-remote` is passed, which documents that a TLS-terminating proxy is in
  front. Responses carry a strict CSP (`default-src 'none'`, scripts and styles from `'self'`
  only), `nosniff`, `X-Frame-Options: DENY`, `no-referrer`, `Cache-Control: no-store` on API
  responses, and HSTS when `AI_IDS_BEHIND_TLS` is set.
- **Privacy.** Alerts are kept in a bounded in-memory buffer and are never written to disk. They
  hold the score, category, ATT&CK technique IDs and a small allow-list of context fields (flow
  identifier, addresses, source port, timestamp, destination port); raw feature vectors are not
  retained. Logs hold request metadata only.
- **Dashboard.** Static files served by the same origin. The script writes untrusted values only
  through `textContent`; there is no inline script, no `innerHTML`, no third-party asset. The read
  key can be passed in the URL fragment (fragments are not sent to the server), is removed from the
  address bar after reading, and is kept in `sessionStorage` for the tab's lifetime so a reload does
  not lose it. Script running on the same origin could read it, which is why the CSP forbids inline
  and third-party script; the read key grants no scoring ability.
- **Demo.** `ai-ids serve --demo` generates random single-use keys and prints them. `ai-ids replay`
  streams the held-out test split of a dataset (real or synthetic) into the service, either at a
  time-compressed rate (`--speed`) or at a fixed flow rate (`--rate`).

## Consequences
- Strong default posture, but the controls are only as good as the deployment: TLS, network
  exposure and key rotation are the operator's responsibility (see the runbook).
- Rate limiting is keyed by the peer address by default. Behind a reverse proxy every client would
  share the proxy's address, so `AI_IDS_TRUSTED_PROXIES` (0 to 5) makes the service trust the last
  N `X-Forwarded-For` entries, using Werkzeug's `ProxyFix`. It is off by default because trusting
  the header without a proxy in front lets a client pick its own bucket; the runbook states what
  the proxy must do.
- State is in memory and per process: alerts are lost on restart and multiple workers would each
  hold their own counters. That matches the data-minimisation goal and a single-process deployment;
  scaling out needs a shared store and a retention decision first.
- The model is still a pickle. Digest and signature checks narrow the risk to a compromised
  artifact store plus a missing signing key (T2).
- A single request scores synchronously on the request thread. Throughput and latency numbers
  must be measured on the target host before any capacity claim; none are made here.
