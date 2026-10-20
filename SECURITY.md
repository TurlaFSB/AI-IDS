# Security Policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub's
["Report a vulnerability"](../../security/advisories/new) form on this repository.
Do not open public issues for security problems. Expect an acknowledgement within
5 business days.

## Scope notes

- Model artifacts are serialised with `joblib` (pickle). Loading an artifact executes code,
  so only load artifacts you trained and stored yourself. Artifacts carry a SHA-256 manifest
  and can be HMAC-signed (`AI_IDS_MODEL_HMAC_KEY`); keep that key out of the repository.
- Never commit packet captures, datasets, API keys, or trained models.
