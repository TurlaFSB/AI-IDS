"""Command-line interface."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from collections.abc import Sequence
from pathlib import Path

import pandas as pd

from ai_ids import __version__
from ai_ids.config import TrainConfig
from ai_ids.data.integrity import dataset_checksums
from ai_ids.data.loader import TIMESTAMP, clean_flows, feature_columns, normalize_columns
from ai_ids.data.split import chronological_split
from ai_ids.data.synthetic import generate_flows
from ai_ids.evaluation.familystudy import run_family_study
from ai_ids.evaluation.holdout import run_holdout
from ai_ids.evaluation.seeds import run_seed_study
from ai_ids.evaluation.transfer import prepare_target, run_transfer
from ai_ids.logging_config import configure_logging
from ai_ids.pipeline import prepare_data, run_adaptive, run_analysis, run_training
from ai_ids.registry import load_detector
from ai_ids.service.replay import ReplaySummary, replay_flows
from ai_ids.service.server import build_app, serve
from ai_ids.service.settings import ServiceSettings, SettingsError

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

    seeds = sub.add_parser("seeds", help="repeat training over several seeds and report the spread")
    seeds.add_argument("--data", type=Path, required=True, help="CSV file or directory")
    seeds.add_argument("--out", type=Path, required=True, help="output JSON file")
    seeds.add_argument("--config", type=Path, help="YAML experiment config")
    seeds.add_argument("--seeds", type=int, nargs="+", default=[42, 43, 44])

    analyze = sub.add_parser(
        "analyze", help="re-run evaluation diagnostics on a saved model without retraining"
    )
    analyze.add_argument("--data", type=Path, required=True, help="CSV file or directory")
    analyze.add_argument("--model-dir", type=Path, required=True, help="saved detector directory")
    analyze.add_argument("--out", type=Path, required=True, help="output JSON file")
    analyze.add_argument("--config", type=Path, help="YAML experiment config used for training")

    adaptive = sub.add_parser(
        "adaptive", help="per-flow adaptive evasion (best-of-grid adversary) on a saved model"
    )
    adaptive.add_argument("--data", type=Path, required=True, help="CSV file or directory")
    adaptive.add_argument("--model-dir", type=Path, required=True, help="saved detector directory")
    adaptive.add_argument("--out", type=Path, required=True, help="output JSON file")
    adaptive.add_argument("--config", type=Path, help="YAML experiment config used for training")
    adaptive.add_argument("--max-flows", type=int, default=20_000, help="flows per class sampled")

    transfer = sub.add_parser(
        "transfer", help="score a different dataset with a saved model, without refitting"
    )
    transfer.add_argument("--data", type=Path, required=True, help="target CSV file or directory")
    transfer.add_argument("--model-dir", type=Path, required=True, help="saved detector directory")
    transfer.add_argument("--out", type=Path, required=True, help="output JSON file")
    transfer.add_argument("--config", type=Path, help="YAML experiment config used for training")
    transfer.add_argument("--max-rows", type=int, help="seeded random sample of the cleaned rows")
    transfer.add_argument(
        "--calibration-fraction",
        type=float,
        help="also calibrate on benign flows from the earliest fraction of the target and test "
        "on the rest (a deployable counterpart of the oracle point)",
    )
    transfer.add_argument(
        "--allow-missing-features",
        action="store_true",
        help="impute features the target lacks instead of failing (weakens the comparison)",
    )

    family = sub.add_parser(
        "family", help="compare one attack family across two datasets (descriptive, no training)"
    )
    family.add_argument("--source-data", type=Path, required=True, help="e.g. CICIDS2017")
    family.add_argument("--target-data", type=Path, required=True, help="e.g. CSE-CIC-IDS2018")
    family.add_argument("--category", default="botnet", help="attack category to compare")
    family.add_argument("--out", type=Path, required=True, help="output JSON file")
    family.add_argument("--model-dir", type=Path, help="optional saved detector for score shift")
    family.add_argument("--config", type=Path, help="YAML experiment config used for training")
    family.add_argument("--max-per-class", type=int, default=50_000)

    serve_cmd = sub.add_parser("serve", help="run the scoring service and dashboard")
    serve_cmd.add_argument("--model-dir", type=Path, required=True, help="saved detector directory")
    serve_cmd.add_argument("--host", default="127.0.0.1")
    serve_cmd.add_argument("--port", type=int, default=8080)
    serve_cmd.add_argument(
        "--allow-remote",
        action="store_true",
        help="allow binding beyond loopback (only behind a TLS-terminating proxy)",
    )
    serve_cmd.add_argument(
        "--demo", action="store_true", help="generate throwaway keys and print how to use them"
    )

    replay_cmd = sub.add_parser("replay", help="replay recorded flows into a running service")
    replay_source = replay_cmd.add_mutually_exclusive_group(required=True)
    replay_source.add_argument("--data", type=Path, help="CSV file or directory")
    replay_source.add_argument("--synthetic", action="store_true", help="use synthetic flows")
    replay_cmd.add_argument("--config", type=Path, help="YAML experiment config used for training")
    replay_cmd.add_argument("--url", default="http://127.0.0.1:8080")
    replay_cmd.add_argument("--speed", type=float, default=120.0, help="time compression factor")
    replay_cmd.add_argument(
        "--rate", type=float, help="send at a steady N flows per second instead of capture timing"
    )
    replay_cmd.add_argument("--batch-size", type=int, default=50)
    replay_cmd.add_argument("--start", help="only flows at or after this timestamp")
    replay_cmd.add_argument("--minutes", type=float, help="only this many minutes from --start")
    replay_cmd.add_argument("--limit", type=int, help="stop after this many flows")

    checksum = sub.add_parser("checksum", help="print SHA-256 digests of dataset files")
    checksum.add_argument("path", type=Path)
    return parser


def _print_progress(summary: ReplaySummary) -> None:
    print(
        f"\rflows={summary.flows_sent} alerts={summary.alerts} "
        f"tp={summary.true_positives} fp={summary.false_positives}",
        end="",
        flush=True,
    )


def _replay_frame(args: argparse.Namespace, config: TrainConfig) -> tuple[pd.DataFrame, list[str]]:
    """The flows to replay: the held-out test split of real data, or of synthetic data."""
    if args.synthetic:
        cleaned, _ = clean_flows(normalize_columns(generate_flows(20_000, config.seed)))
        split = chronological_split(cleaned, config.split_fractions)
        features = feature_columns(cleaned)
    else:
        split, features, _ = prepare_data(args.data, config)
    # The split is stored grouped by class; select in capture-time order so filters and limits
    # describe real time windows instead of whichever class happens to come first.
    frame = split.test.sort_values(TIMESTAMP, kind="stable")
    if args.start:
        frame = frame[frame[TIMESTAMP] >= pd.Timestamp(args.start)]
        if args.minutes:
            frame = frame[
                frame[TIMESTAMP] < pd.Timestamp(args.start) + pd.Timedelta(minutes=args.minutes)
            ]
    if args.limit:
        frame = frame.head(args.limit)
    if frame.empty:
        raise SystemExit("no flows selected for replay")
    return frame, features


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

    if args.command == "seeds":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        study = run_seed_study(args.data, config, args.seeds)
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(study, indent=2) + "\n")
        for name, metrics in study["detectors"].items():
            parts = ", ".join(
                f"{key}={metrics[key]['mean']:.4f}+/-{metrics[key]['std']:.4f}"
                for key in ("recall", "false_positive_rate", "precision")
            )
            print(f"{name}: {parts} (n={len(args.seeds)})")
        return 0

    if args.command == "serve":
        try:
            if args.demo:
                settings = ServiceSettings(
                    api_key=secrets.token_urlsafe(24), read_key=secrets.token_urlsafe(24)
                )
            else:
                settings = ServiceSettings.from_env()
        except SettingsError as error:
            print(f"configuration error: {error}", file=sys.stderr)
            return 2
        key = os.environ.get(HMAC_KEY_ENV)
        app = build_app(args.model_dir, settings, hmac_key=key.encode() if key else None)
        if args.demo:
            print("Demo keys (local use only; they change on every start):")
            print(f"  dashboard: http://{args.host}:{args.port}/#key={settings.read_key}")
            print(f"  replay:    AI_IDS_API_KEY={settings.api_key} ai-ids replay --synthetic ...")
        serve(app, args.host, args.port, allow_remote=args.allow_remote)
        return 0

    if args.command == "replay":
        api_key = os.environ.get("AI_IDS_API_KEY")
        if not api_key:
            print(
                "configuration error: set AI_IDS_API_KEY to the service's score key",
                file=sys.stderr,
            )
            return 2
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        frame, features = _replay_frame(args, config)
        summary = replay_flows(
            frame,
            features,
            base_url=args.url,
            api_key=api_key,
            speed=args.speed,
            rate=args.rate,
            batch_size=args.batch_size,
            on_batch=_print_progress,
        )
        print()
        print(json.dumps(summary.to_dict(), indent=2))
        return 0

    if args.command == "analyze":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        key = os.environ.get(HMAC_KEY_ENV)
        analysis = run_analysis(
            args.data, args.model_dir, config, hmac_key=key.encode() if key else None
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(analysis, indent=2, default=str) + "\n")
        test = analysis["evaluation"]["test"]
        print(
            f"{analysis['detector']}: recall={test['recall']:.4f} "
            f"fpr={test['false_positive_rate']:.4f} split_verified="
            f"{analysis['split_check']['verified']}"
        )
        return 0

    if args.command == "adaptive":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        key = os.environ.get(HMAC_KEY_ENV)
        outcome = run_adaptive(
            args.data,
            args.model_dir,
            config,
            hmac_key=key.encode() if key else None,
            max_flows=args.max_flows,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(outcome, indent=2, default=str) + "\n")
        study_result = outcome["adaptive_evasion"]
        control = study_result["benign_control"]
        print(
            f"{outcome['detector']}: clean recall={study_result['clean_recall']:.4f} "
            f"adaptive recall={study_result['adaptive_recall']:.4f} "
            f"benign flagged under any combination="
            f"{control['flagged_under_any_combination']:.4f} "
            f"(clean fpr {control['clean_false_positive_rate']:.4f})"
        )
        return 0

    if args.command == "transfer":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        key = os.environ.get(HMAC_KEY_ENV)
        detector = load_detector(args.model_dir, hmac_key=key.encode() if key else None)
        result = run_transfer(
            args.data,
            args.model_dir,
            config,
            detector,
            allow_missing=args.allow_missing_features,
            max_rows=args.max_rows,
            calibration_fraction=args.calibration_fraction,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=2, default=str) + "\n")
        for name in ("stored_threshold", "oracle_recalibrated"):
            point = result[name]
            print(
                f"{result['detector']} [{name}]: recall={point['recall']:.4f} "
                f"fpr={point['false_positive_rate']:.4f} precision={point['precision']:.4f} "
                f"pr_auc={point['pr_auc']:.4f}"
            )
        local_study = result.get("local_calibration_study")
        if local_study:
            for name in ("local_calibration", "stored_threshold_same_flows"):
                point = local_study[name]
                print(
                    f"{result['detector']} [{name}, later flows]: "
                    f"recall={point['recall']:.4f} fpr={point['false_positive_rate']:.4f} "
                    f"precision={point['precision']:.4f}"
                )
        return 0

    if args.command == "family":
        config = TrainConfig.from_yaml(args.config) if args.config else TrainConfig()
        key = os.environ.get(HMAC_KEY_ENV)
        reference = (
            load_detector(args.model_dir, hmac_key=key.encode() if key else None)
            if args.model_dir
            else None
        )
        source, _, _ = prepare_target(
            args.source_data,
            pm_fix_before_hour=config.timestamp_pm_fix_before_hour,
            dayfirst=config.timestamp_dayfirst,
        )
        target, _, _ = prepare_target(args.target_data, dayfirst=config.timestamp_dayfirst)
        held_out = chronological_split(source, config.split_fractions).test
        study = run_family_study(
            source,
            target,
            args.category,
            detector=reference,
            max_per_class=args.max_per_class,
            seed=config.seed,
            scoring_source=held_out,
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(study, indent=2, default=str) + "\n")
        comparison = study["comparison"]
        print(
            f"{args.category}: source flows {study['source_flows']['family']}, "
            f"target flows {study['target_flows']['family']}, "
            f"spearman of feature effects {comparison.get('spearman_of_effects')}"
        )
        for row in comparison.get("strongest", [])[:8]:
            auc_pair = f"auc source {row['auc_source']:.3f} target {row['auc_target']:.3f}"
            print(f"  {row['feature']}: {auc_pair}")
        return 0

    if args.command == "checksum":
        json.dump(dataset_checksums(args.path), sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 0

    return 2
