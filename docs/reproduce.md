# Reproducing the results

Two paths: a minute-scale check that the pipeline is deterministic and wired together (no download), and
the real-data runs behind every number in the README. Neither needs anything but Python 3.11 or newer.

## 1. Pipeline check on synthetic data (about a minute)

```bash
git clone https://github.com/TurlaFSB/AI-IDS.git && cd AI-IDS
python -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install --require-hashes -r requirements/dev.txt && pip install --no-deps -e .
./scripts/reproduce_synthetic.sh                       # Windows: run it in WSL or Git Bash
```

The script generates 30,000 synthetic flows, trains all detectors **twice with the same seed and fails
unless the two reports agree exactly** (it prints a digest of the results), then runs leave-one-family-out,
a grouped leave-out, the adaptive-evasion study and builds the results page. CI runs it on every push.
Synthetic data proves the pipeline is reproducible; it says nothing about detection on real traffic.

## 2. Real data

Download CICIDS2017 as described in the [README](../README.md#datasets), then record digests so the run can
be traced to exact files:

```bash
ai-ids checksum data/raw/TrafficLabelling
ai-ids train --data data/raw/TrafficLabelling --out models/robust3 --config configs/robustness.yaml
```

Every `report.json` records the dataset file digests, the package version, the git commit and whether the
working tree was dirty, the full configuration and the seed. Observed wall-clock times on a 16 GB Windows
laptop (CICIDS2017, 2.49 million flows after cleaning):

| Step | Command | Time |
|---|---|---|
| Train four detectors and two fusions | `train --config configs/corrected.yaml` | about 20 minutes |
| Leave-one-family-out | `holdout --config configs/corrected.yaml` | about 8 minutes |
| Destination-port ablation | `train --config configs/ablation.yaml` | about 18 minutes |
| Diagnostics on a saved model | `analyze` | about 1 minute |

The studies, each writing one JSON file that `ai-ids report-html` can render:

| Question | Command |
|---|---|
| Spread over seeds | `ai-ids seeds --config configs/corrected.yaml` |
| Unseen families, singly and in related groups | `ai-ids holdout --group dos,ddos --group portscan,infiltration` |
| Evasion by a per-flow adversary | `ai-ids adaptive --model-dir models/corrected/random_forest_aug` |
| A second dataset, threshold fixed | `ai-ids transfer --data data/raw/cse2018 --model-dir ...` |
| Corrected labels vs the authors' script | `ai-ids relabel-check --notebook <their notebook>` |

## What is and is not deterministic

Seeds are fixed for the split, the models, the bootstrap and the evasion sampling. Results are exact on one
machine and software stack; across platforms, library versions or thread counts, floating-point
differences can change the last digits, which is why the hash-locked requirements are part of the method.
Latency numbers depend on the machine and are not reproducible. Corrected-label results depend on the
rule table (`RULESET_VERSION`, recorded in the report); a result is only comparable with another under the
same version.
