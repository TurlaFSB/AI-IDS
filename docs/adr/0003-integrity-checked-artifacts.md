# 0003. Integrity-checked model artifacts

Status: Accepted (2026-10-20)

## Context
Models are serialised with joblib, which is pickle-based: loading a tampered artifact executes
arbitrary code. Models move between training hosts, storage, and serving hosts.

## Decision
Every artifact has a manifest recording its SHA-256 digest, threshold, features, library versions,
and metadata. The manifest can be signed with HMAC-SHA256 using a key supplied through the
environment. Loading verifies the signature (when keyed) and digest before deserialising, and a
keyed load rejects unsigned manifests (no downgrade).

## Consequences
- Tampering at rest is detected; HMAC protects against an attacker who can write to storage but
  does not hold the key.
- Key management is the operator's responsibility.
- Pickle remains a risk if signing is disabled; a non-executable model format is a roadmap item.
