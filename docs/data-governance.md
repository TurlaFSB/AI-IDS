# Data governance

## Dataset provenance

- **Dataset:** CIC-IDS-2017, Canadian Institute for Cybersecurity, University of New Brunswick.
- **Source:** <https://www.unb.ca/cic/datasets/ids-2017.html>
- **Citation:** I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New Intrusion
  Detection Dataset and Intrusion Traffic Characterization", ICISSP 2018.
- Obey the dataset's terms of use and citation requirements. Check the licence information on the
  source site before any redistribution or commercial use.
- Known quality issues are documented in Engelen, Rimmer & Joosen, "Troubleshooting an Intrusion
  Detection Dataset: the CICIDS2017 Case Study" (2021). Handling is described in the model card.

## Integrity and traceability

- Record SHA-256 digests of every input file with `ai-ids checksum <dir>` and keep them with the
  experiment record.
- Every training run writes `report.json` containing configuration, dataset cleaning statistics,
  class counts per split, library versions, and the git commit.

## Personal data

IP addresses and timestamps in flow records can identify individuals (GDPR Recital 30; CCPA
"personal information").

- **Minimisation:** identifiers (flow ID, IPs, source port, timestamp) are excluded from model
  features. They are used only for ordering and, in future, enrichment.
- **No committed data:** datasets, packet captures, and flow logs are git-ignored and must never
  be committed.
- **Public research data:** CIC-IDS-2017 was captured in a controlled testbed; production data
  would need a lawful basis, a retention schedule, and access control before use.
- **Retention (production use):** keep raw flow data only as long as needed for detection and
  retraining; define and document the period before deployment.
- **Logs:** application logs must not contain raw flow records or credentials.
- **Reports:** `report.json` can list the most frequent source and destination IPs among false
  positives (`fp_profile_columns`). For the public testbed dataset this is harmless; with real
  traffic, remove the IP columns from `fp_profile_columns` or treat the report as personal data.
- **Timestamps:** CIC-IDS-2017 dates are day-first (`4/7/2017` is 4 July 2017); the loader parses
  them accordingly (`timestamp_dayfirst`).

## Secrets

API keys and signing keys live in environment variables or a git-ignored `.env`. Only
`.env.example` is committed.
