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

## Corrected CICIDS2017 labels
`ai-ids relabel` and `corrected_labels: true` re-label CICIDS2017 flows from attack timelines in the
published literature (ADR 0013). The rules cover attack windows, internal and attacker addresses and
ports; they describe a public testbed capture and contain no personal data. Flows labelled "attempted"
are dropped. Corrected-label runs must be reported separately from original-label runs.

## CSE-CIC-IDS2018 files used for the transfer test
- Each of the three day files has exactly 1,048,575 rows (Excel's limit minus the header), so they
  were almost certainly truncated at export; counts of some attack classes are partial.
- `rst_flag_count` and `ece_flag_count` are identical in all but one of 1,048,575 rows of the Bot day,
  so they carry the same information in these files.
- A handful of flows (9 across the three files) are dated 1970; they are set to missing and excluded
  from time-based steps.
- The files have no source or destination addresses.

## Scoring service

- Alerts (score, category, ATT&CK IDs and an allow-list of context fields that may include
  source and destination IPs and a timestamp) are held in a bounded in-memory buffer
  (`AI_IDS_ALERT_BUFFER`) and are not written to disk by the service. Raw feature vectors are not
  retained.
- Request logs hold metadata only (request ID, path, status, duration, flow count).
- The minimisation lever is the client: omit `source_ip` and `destination_ip` from requests if the
  analyst does not need them. The demo and replay use a public testbed dataset or synthetic data.
- For production, define the lawful basis, who may hold the read key, and how long the
  operator's log pipeline retains request logs before deployment.

## Secrets

API keys and signing keys live in environment variables or a git-ignored `.env`. Only
`.env.example` is committed.
