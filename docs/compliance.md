# Standards alignment

This document maps project capabilities to widely used frameworks. It states what the
**software** provides; organisational controls (policies, staffing, deployment hardening)
are outside the scope of this repository. Mapping is at control-family or category level and
is an engineering aid, not a certification or audit claim.

Status: **Implemented**, **Partial**, **Planned**.

## NIST Cybersecurity Framework 2.0

| Function / category | Project capability | Status |
|---|---|---|
| DETECT: Continuous Monitoring (DE.CM) | Flow-level network anomaly and attack detection | Implemented (offline); live capture planned |
| DETECT: Adverse Event Analysis (DE.AE) | Scored events, ATT&CK technique tagging, calibrated alert threshold | Partial |
| PROTECT: Data Security (PR.DS) | Artifact integrity (SHA-256, HMAC); no datasets or secrets in the repository | Implemented |
| PROTECT: Platform Security (PR.PS) | Secure SDLC: typed code, tests, SAST, dependency audit in CI | Implemented |
| GOVERN: Supply Chain Risk Management (GV.SC) | Hash-locked dependencies, SHA-pinned CI actions, pinned container base image, SBOM, vulnerability audit and image scan, Dependabot | Implemented |
| RESPOND: Incident Analysis (RS.AN) | ATT&CK-tagged alerts (implemented); threat-intel enrichment not built | Partial |
| RECOVER | Model rollback via versioned artifacts | Planned |

## NIST SP 800-53 Rev. 5 (selected controls)

| Control | Relevance | Status |
|---|---|---|
| SI-4 System Monitoring | Detection of anomalous network activity | Partial |
| SI-7 Software, Firmware, and Information Integrity | Verified model artifacts | Implemented |
| AU-2 / AU-3 / AU-12 Audit events, content, generation | Structured JSON logging with timestamps and context | Partial |
| SA-11 Developer Testing and Evaluation | Unit and end-to-end tests with a coverage gate | Implemented |
| RA-5 Vulnerability Monitoring and Scanning | `pip-audit`, Trivy image scan, Dependabot | Implemented |
| SR-3 / SR-4 Supply chain controls and provenance | Hash-locked dependencies, pinned actions and base image, SBOM | Implemented |
| CM-2 / CM-3 Baseline configuration, change control | Config-driven runs, pinned lower bounds, CI-gated changes | Partial |
| SC-13 Cryptographic Protection | HMAC-SHA256 and SHA-256 for artifact integrity | Implemented |
| IA-2 / AC-3 Authentication and access enforcement | Bearer-key authentication with score and read scopes (no per-user identity) | Partial |
| SC-5 / SC-7 Denial-of-service protection, boundary protection | Rate limiting, size and batch limits; TLS is the operator's proxy | Partial |
| SI-10 Information Input Validation | Strict request schema, value and size validation | Implemented |

## MITRE ATT&CK

Detected attack types are mapped to technique IDs in `ai_ids.labels` (for example PortScan to
T1046 Network Service Discovery, brute-force attacks to T1110). The mapping is analyst-assigned
and approximate; it exists to enrich alerts, not as ground truth.

## OWASP ASVS (scoring service)

The service is designed against ASVS Level 2 and has **not** been independently assessed; the
table is a self-assessment of what the code does, with the gaps stated.

| Area | Control in this project | Gap |
|---|---|---|
| V2 Authentication | Bearer keys, 16-character minimum, constant-time comparison, distinct score and read keys | No per-user identity, MFA, lockout or expiry |
| V3 Session | No server-side sessions or cookies; the dashboard keeps the read key in `sessionStorage` | Same-origin script could read it |
| V4 Access control | Scope check on every API route; public routes are only probes, the spec and static files | Two coarse scopes only |
| V5 Validation, encoding | Strict schema, size and range limits; values never echoed; dashboard uses `textContent` | |
| V7 Errors, logging | JSON errors without traces; structured logs without keys, bodies or features | No tamper-evident audit log |
| V8 Data protection | Alerts in memory only, bounded; `Cache-Control: no-store` on API responses | |
| V9 Communication | HSTS when behind TLS; refuses non-loopback binding without explicit opt-in | TLS itself is the operator's proxy |
| V12/V13 API | JSON only (415 otherwise), body and batch limits, rate limiting, OpenAPI spec | Rate limit keyed by peer address |
| V14 Configuration | Secrets from the environment only, security headers and strict CSP, hash-pinned dependencies, scanned image | |

CSRF: the API is authenticated by an `Authorization` header that browsers do not attach
automatically, and there are no cookies, so classic CSRF does not apply; `form-action 'none'` and
`frame-ancestors 'none'` are also set.

OWASP Top 10 (2021) coverage is mapped in the table above and in the threat model (A01 access
control, A03 injection, A05 misconfiguration, A06 vulnerable components, A08 integrity).

## Privacy

IP addresses are treated as personal data. See `docs/data-governance.md`.
