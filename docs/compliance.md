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
| RESPOND: Incident Analysis (RS.AN) | ATT&CK-tagged alerts with threat-intel context | Planned |
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
| IA-2 / AC-3 Authentication and access enforcement | Service authentication and authorisation | Planned |

## MITRE ATT&CK

Detected attack types are mapped to technique IDs in `ai_ids.labels` (for example PortScan to
T1046 Network Service Discovery, brute-force attacks to T1110). The mapping is analyst-assigned
and approximate; it exists to enrich alerts, not as ground truth.

## OWASP ASVS (planned service)

The scoring service and dashboard will be built to ASVS Level 2: authentication, session and
access control, input validation, output encoding, CSRF protection, security headers, TLS,
logging without sensitive data, and rate limiting.

## Privacy

IP addresses are treated as personal data. See `docs/data-governance.md`.
