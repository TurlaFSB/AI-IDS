#!/usr/bin/env bash
# Reproduce the whole pipeline end to end on synthetic data, with no download.
#
#   scripts/reproduce_synthetic.sh [WORKDIR]
#
# It trains twice and fails unless the two runs agree exactly (fixed seeds), then runs the leave-out,
# grouped leave-out and adaptive-evasion studies and builds the results page. Synthetic data shows that
# the pipeline is deterministic and wired together; it says nothing about detection on real traffic.
# Needs the package installed (`pip install -e .`); takes a few minutes on a laptop.
set -euo pipefail
cd "$(dirname "$0")/.."

work="${1:-$(mktemp -d)}"
mkdir -p "$work"
config="configs/light.yaml"
echo "working directory: $work"

step() { printf '\n== %s ==\n' "$1"; }

step "synthetic data"
ai-ids synth --out "$work/synthetic.csv" --rows 30000

step "train, run 1 and run 2 (same seed)"
ai-ids train --data "$work/synthetic.csv" --out "$work/run1" --config "$config"
ai-ids train --data "$work/synthetic.csv" --out "$work/run2" --config "$config"

step "the two runs must agree exactly"
python -I - "$work/run1/report.json" "$work/run2/report.json" <<'PY'
import hashlib
import json
import sys

# Timings and the environment block legitimately differ; everything that is a result must not.
KEYS = ("calibration", "test", "operating_points", "per_attack_recall", "per_category_recall")


def results(path):
    with open(path, encoding="utf-8") as handle:
        report = json.load(handle)
    return {
        "dataset": report["dataset"]["files_sha256"],
        "models": {
            name: {key: model[key] for key in KEYS} for name, model in report["models"].items()
        },
    }


first, second = results(sys.argv[1]), results(sys.argv[2])
if first != second:
    for name in first["models"]:
        if first["models"][name] != second["models"][name]:
            print(f"DIFFERENT: {name}", file=sys.stderr)
    sys.exit("runs with the same seed disagree: the pipeline is not reproducible")
digest = hashlib.sha256(json.dumps(first, sort_keys=True).encode()).hexdigest()
print(f"identical results across runs; digest {digest}")
PY

step "leave-one-family-out and a grouped leave-out"
ai-ids holdout --data "$work/synthetic.csv" --out "$work/holdout.json" --config "$config"
ai-ids holdout --data "$work/synthetic.csv" --out "$work/holdout_grouped.json" --config "$config" \
  --group dos,portscan --group botnet

step "adaptive evasion against the Random Forest"
ai-ids adaptive --data "$work/synthetic.csv" --model-dir "$work/run1/random_forest" \
  --out "$work/adaptive.json" --config "$config"

step "results page"
ai-ids report-html --run synthetic="$work/run1/report.json" \
  --adaptive random_forest="$work/adaptive.json" --holdout single="$work/holdout.json" \
  --holdout grouped="$work/holdout_grouped.json" \
  --note "Synthetic data: shows the pipeline, not detection quality." \
  --out "$work/results.html"
test -s "$work/results.html"
if grep -qi "<script" "$work/results.html"; then
  echo "results page contains a script element" >&2
  exit 1
fi

printf '\nreproduction OK. Outputs are in %s\n' "$work"
