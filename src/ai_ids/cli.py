"""Command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from ai_ids import __version__
from ai_ids.config import TrainConfig
from ai_ids.data.synthetic import generate_flows
from ai_ids.evaluation.holdout import run_holdout
from ai_ids.logging_config import configure_logging
from ai_ids.pipeline import prepare_data, run_training

HMAC_KEY_ENV = "AI_IDS_MODEL_HMAC_KEY"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ai-ids", description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--log-level", default="INFO")
    sub = parser.add_subparsers(dest="command", required=True)

    synth = sub.add_parser("synth", help="write a synthetic CICIDS2017-style CSV")
    synth.add_argument("--out", type=Path, required=True)
    synth.add_argument("--rows", type=int, default=20_000)
    synth.add_argument("--seed", type=int, default=42)

    train = sub.add_parser("train", help="train and evaluate detectors")
    train.add_argument("--data", type=Path, required=True, help="CSV file or directory")
    train.add_argument("--out", type=Path, required=True, help="output directory")
    train.add_argument("--config", type=Path, help="YAML experiment config")

    holdout = sub.add_parser(
        "holdout", help="leave-one-attack-family-out generalisation test (slow)"
    )
    holdout.add_argument("--data", type=Path, required=True, help="CSV file or directory")
    holdout.add_argument("--out", type=Path, required=True, help="output JSON file")
    holdout.add_argument("--config", type=Path, help="YAML experiment config")

    checksum = sub.add_parser("checksum", help="print SHA-256 digests of dataset files")
    checksum.add_argument("path", type=Path)
    return parser


def _checksums(path: Path) -> dict[str, str]:
    files = sorted(path.glob("*.csv")) if path.is_dir() else [path]
    result = {}
    for file in files:
        digest = hashlib.sha256()
        with file.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1 << 20), b""):
                digest.update(chunk)
        result[file.name] = digest.hexdigest()
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    configure_logging(args.log_level)

    if args.command == "synth":
        args.out.parent.mkdir(parents=True, exist_ok=True)
        # latin-1 matches the encoding quirks of the real CICIDS2017 files.
        generate_flows(args.rows, args.seed).to_csv(args.out, index=False, encoding="latin-1")
        return 0

    if args.command == "train":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        key = os.environ.get(HMAC_KEY_ENV)
        report = run_training(args.data, args.out, config, hmac_key=key.encode() if key else None)
        for name, result in report["models"].items():
            test = result["test"]
            print(
                f"{name}: recall={test['recall']:.4f} fpr={test['false_positive_rate']:.4f} "
                f"precision={test['precision']:.4f} pr_auc={test['pr_auc']:.4f} "
                f"macro_recall={result['macro_recall']:.4f}"
            )
        return 0

    if args.command == "holdout":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        split, features, _ = prepare_data(args.data, config)
        holdout_report = run_holdout(split, features, config)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(holdout_report, indent=2) + "\n")
        for family, result in holdout_report["families"].items():
            print(
                f"{family}: recall_unseen={result['recall_unseen']:.4f} "
                f"fpr={result['false_positive_rate']:.4f} support={result['test_support']}"
            )
        return 0

    if args.command == "checksum":
        json.dump(_checksums(args.path), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    return 2
