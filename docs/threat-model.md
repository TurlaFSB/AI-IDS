# Threat model (STRIDE)

Scope: the AI-IDS training pipeline and model artifacts (v0.1), with forward-looking entries
for the planned scoring service. Status values: **Mitigated**, **Partial**, **Planned**.

## Assets

| Asset | Why it matters |
|---|---|
| Training data | Poisoned data degrades or backdoors the detector |
| Trained model artifacts | Loading a tampered artifact executes attacker code (pickle) |
| Alert threshold | Raising it silently blinds the detector |
| API keys (threat intel) | Abuse and quota theft |
| Flow metadata (IPs, ports, timestamps) | Personal data under GDPR |

## Trust boundaries

1. Dataset source to training host (data provenance).
2. Training host to artifact storage to serving host (artifact integrity).
3. Network traffic to the scoring service (hostile input, planned).

## Threats

| ID | STRIDE | Threat | Mitigation | Status |
|---|---|---|---|---|
| T1 | Tampering | Attacker replaces `model.joblib` in storage | SHA-256 manifest verified before load; optional HMAC-SHA256 signature over the manifest | Mitigated (HMAC requires key management by the operator) |
| T2 | Elevation of privilege | Malicious pickle executes code when an artifact is loaded | Only load artifacts from controlled storage; digest and signature checks; documented in SECURITY.md. Moving to a non-executable format is a roadmap item | Partial |
| T3 | Tampering | Training-data poisoning (mislabelled or crafted flows) | Dataset checksums recorded; chronological splits; planned: retraining gated by champion/challenger evaluation on held-out data | Partial |
| T4 | Tampering | Threshold manipulation in the manifest | Manifest is signed when a key is configured; threshold is recorded in the report | Mitigated with signing |
| T5 | Spoofing | Unauthenticated callers submit flows or read alerts | Authentication and authorisation (OWASP ASVS L2) for the service | Planned |
| T6 | Information disclosure | Logs or alerts expose IPs and other personal data | Structured logs exclude flow payloads; retention and minimisation rules in `docs/data-governance.md` | Partial |
| T7 | Information disclosure | Secrets committed to the repository | `.gitignore`, `.env.example` only, pre-commit private-key detection, GitHub secret scanning | Mitigated |
| T8 | Denial of service | Oversized or high-rate input exhausts the scoring service | Input validation, rate limiting, resource limits | Planned |
| T9 | Repudiation | No record of who retrained or promoted a model | Manifest records creation time, environment, and metrics; promotion audit log | Partial |
| T10 | Evasion (ML-specific) | Attacker shapes traffic to stay below the threshold | Per-attack recall reporting reveals blind spots; ensembling with an unsupervised detector; adversarial evaluation | Partial |
| T11 | Tampering (supply chain) | Malicious or vulnerable dependency | `pip-audit`, `bandit`, SBOM in CI, Dependabot | Mitigated (hash-locked dependencies planned) |

## Residual risks

- Detection quality on real traffic is unproven until evaluated on real data and in a real
  deployment; published datasets differ from production networks.
- Pickle-based artifacts remain a code-execution risk if storage is compromised and signing
  is not enabled.
