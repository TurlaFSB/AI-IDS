# Threat model (STRIDE)

Scope: the AI-IDS training pipeline, model artifacts, and the scoring service with its dashboard
(ADR 0010). Status values: **Mitigated**, **Partial**.

## Assets

| Asset | Why it matters |
|---|---|
| Training data | Poisoned data degrades or backdoors the detector |
| Trained model artifacts | Loading a tampered artifact executes attacker code (pickle) |
| Alert threshold | Raising it silently blinds the detector |
| Service API keys (score and read) | Submitting traffic, reading alerts and metrics |
| Flow metadata (IPs, ports, timestamps) | Personal data under GDPR |

## Trust boundaries

1. Dataset source to training host (data provenance).
2. Training host to artifact storage to serving host (artifact integrity).
3. Network traffic to the scoring service (hostile input), and the browser that views the dashboard.

## Threats

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T1 | Tampering | Attacker replaces `model.joblib` in storage | SHA-256 manifest verified before load; optional HMAC-SHA256 signature over the manifest | Mitigated (HMAC requires key management by the operator) |
| T2 | Elevation of privilege | Malicious pickle executes code when an artifact is loaded | Only load artifacts from controlled storage; digest and signature checks; documented in SECURITY.md. Moving to a non-executable format is a roadmap item | Partial |
| T3 | Tampering | Training-data poisoning (mislabelled or crafted flows) | Dataset checksums recorded; chronological splits; planned: retraining gated by champion/challenger evaluation on held-out data | Partial |
| T4 | Tampering | Threshold manipulation in the manifest | Manifest is signed when a key is configured; threshold is recorded in the report | Mitigated with signing |
| T5 | Spoofing | Unauthenticated callers submit flows or read alerts | Bearer keys with separate score and read scopes, constant-time comparison, minimum length, keys only from the environment, 401 without detail. No per-user identity, expiry or lockout; one shared key per scope | Mitigated for a single-tenant deployment |
| T6 | Information disclosure | Logs or alerts expose IPs and other personal data | Structured logs exclude flow payloads; retention and minimisation rules in `docs/data-governance.md` | Partial |
| T7 | Information disclosure | Secrets committed to the repository | `.gitignore`, `.env.example` only, pre-commit private-key detection, GitHub secret scanning | Mitigated |
| T8 | Denial of service | Oversized or high-rate input exhausts the scoring service | Strict schema validation, body and batch caps, per-address token-bucket rate limit applied before authentication, bounded buffers. The limit is keyed by peer address, so behind a proxy it needs proxy-side limits; scoring runs on the request thread and no capacity figure has been measured | Partial |
| T9 | Repudiation | No record of who retrained or promoted a model | Manifest records creation time, environment, and metrics; promotion audit log | Partial |
| T10 | Evasion (ML-specific) | Attacker shapes traffic to stay below the threshold | Measured: padding every packet cut Random Forest recall from 0.99 to 0.51 and forward-only padding to 0.57 in feature space. Symmetric evasion-aware training restores recall to 0.96-0.99 under padding and slowing with no increase in benign false positives (an earlier attack-only design failed its benign control). Gradient boosting pays a large clean false-positive cost for the same robustness. Feature-space and single-seed; packet-level and adaptive evaluation not yet done | Partially mitigated (feature space) |
| T11 | Tampering (supply chain) | Malicious or vulnerable dependency, build action, or base image | Hash-locked dependencies installed with `--require-hashes`, SHA-pinned GitHub Actions, digest-pinned base image, `pip-audit`, `bandit`, Trivy image scan, SBOM, Dependabot (ADR 0006) | Mitigated |
| T12 | Tampering / Information disclosure | Script injection through attacker-controlled flow fields reflected in the dashboard (XSS) | Dashboard writes untrusted values with `textContent` only; strict same-origin CSP with no inline script; context fields are length- and character-restricted | Mitigated |
| T13 | Information disclosure | Error messages, headers or logs reveal keys, stack traces or client data | JSON errors without traces, validation messages never echo values, keys and bodies never logged, `Cache-Control: no-store` on API responses | Mitigated |
| T14 | Information disclosure | Traffic or keys intercepted in transit | The service has no TLS; it refuses non-loopback binding without `--allow-remote`, HSTS is sent when `AI_IDS_BEHIND_TLS` is set. TLS is the operator's proxy | Partial (operator-dependent) |
| T15 | Information disclosure | Read key stolen from the browser | Key lives in `sessionStorage` for the tab and is removed from the address bar; read scope cannot submit flows. Same-origin script could read it, mitigated by the CSP | Partial |

## Residual risks

- Detection quality on real traffic is unproven until evaluated on real data and in a real
  deployment; published datasets differ from production networks.
- Pickle-based artifacts remain a code-execution risk if storage is compromised and signing
  is not enabled.
- The service keeps alerts, including IP addresses, in memory; anyone holding the read key can
  see them. There is no per-user access control or audit trail of who read what.
- Shared keys cannot be revoked per client. Rotation means restarting the service.
- The service has not been load-tested or externally penetration-tested; the controls above are
  verified by the project's own tests (`tests/test_service.py`) and by manual browser checks.
