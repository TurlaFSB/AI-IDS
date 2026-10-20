"""Synthetic flow generator that mimics the CICIDS2017 CSV layout.

Used for tests, demos and CI so that the pipeline can run without the real dataset.
Results on synthetic data say nothing about real-world detection performance.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

# (raw label, share of rows)
_CLASS_MIX: tuple[tuple[str, float], ...] = (
    ("BENIGN", 0.80),
    ("DoS Hulk", 0.06),
    ("PortScan", 0.06),
    ("FTP-Patator", 0.04),
    ("Web Attack \x96 Brute Force", 0.02),
    ("Bot", 0.02),
)

_RAW_COLUMNS = {
    "destination_port": " Destination Port",
    "flow_duration": " Flow Duration",
    "total_fwd_packets": " Total Fwd Packets",
    "total_backward_packets": " Total Backward Packets",
    "fwd_packet_length_mean": " Fwd Packet Length Mean",
    "flow_bytes_s": "Flow Bytes/s",
    "flow_packets_s": " Flow Packets/s",
    "flow_iat_mean": " Flow IAT Mean",
    "syn_flag_count": " SYN Flag Count",
    "ack_flag_count": " ACK Flag Count",
    "init_win_bytes_forward": "Init_Win_bytes_forward",
    "active_mean": "Active Mean",
}


def _class_features(rng: np.random.Generator, label: str, n: int) -> dict[str, np.ndarray]:
    def lognorm(mean: float, sigma: float = 1.0) -> np.ndarray:
        return rng.lognormal(mean, sigma, n)

    base = {
        "destination_port": rng.choice([80, 443, 53, 22, 8080], n).astype(float),
        "flow_duration": lognorm(11.0, 2.0),
        "total_fwd_packets": rng.poisson(8, n).astype(float) + 1,
        "total_backward_packets": rng.poisson(7, n).astype(float),
        "fwd_packet_length_mean": lognorm(4.5, 0.8),
        "flow_bytes_s": lognorm(8.0, 2.0),
        "flow_packets_s": lognorm(3.5, 1.5),
        "flow_iat_mean": lognorm(10.0, 2.0),
        "syn_flag_count": rng.binomial(1, 0.3, n).astype(float),
        "ack_flag_count": rng.binomial(1, 0.6, n).astype(float),
        "init_win_bytes_forward": rng.choice([229, 8192, 29200, 65535], n).astype(float),
        "active_mean": lognorm(9.0, 2.0),
    }
    if label.startswith("DoS"):
        base["flow_duration"] = lognorm(13.0, 1.0)
        base["total_fwd_packets"] = rng.poisson(5, n).astype(float) + 1
        base["flow_packets_s"] = lognorm(1.5, 1.0)
        base["destination_port"] = np.full(n, 80.0)
    elif label == "PortScan":
        base["destination_port"] = rng.integers(1, 65535, n).astype(float)
        base["flow_duration"] = lognorm(5.0, 1.5)
        base["total_fwd_packets"] = np.ones(n)
        base["total_backward_packets"] = rng.binomial(1, 0.3, n).astype(float)
        base["syn_flag_count"] = np.ones(n)
    elif label == "FTP-Patator":
        base["destination_port"] = np.full(n, 21.0)
        base["total_fwd_packets"] = rng.poisson(12, n).astype(float) + 4
        base["flow_duration"] = lognorm(10.0, 0.8)
    elif label.startswith("Web Attack"):
        base["destination_port"] = np.full(n, 80.0)
        base["fwd_packet_length_mean"] = lognorm(5.8, 0.6)
        base["flow_bytes_s"] = lognorm(9.5, 1.2)
    elif label == "Bot":
        base["destination_port"] = rng.choice([8080, 443, 8443], n).astype(float)
        base["flow_iat_mean"] = lognorm(13.0, 0.5)
        base["active_mean"] = lognorm(7.0, 0.5)
    return base


def generate_flows(n_rows: int = 20_000, seed: int = 42) -> pd.DataFrame:
    """Return a raw (uncleaned) frame laid out like a CICIDS2017 CSV, including its quirks."""
    rng = np.random.default_rng(seed)
    counts = rng.multinomial(n_rows, [share for _, share in _CLASS_MIX])
    frames = []
    for (label, _), n in zip(_CLASS_MIX, counts, strict=True):
        if n == 0:
            continue
        features = _class_features(rng, label, int(n))
        frames.append(pd.DataFrame({_RAW_COLUMNS[k]: v for k, v in features.items()}))
        frames[-1][" Label"] = label
    df = pd.concat(frames, ignore_index=True).sample(frac=1.0, random_state=seed)
    df = df.reset_index(drop=True)

    # Capture window 09:00-17:00 on a single day, stored on a 12-hour clock like the source.
    offsets = np.sort(rng.integers(0, 8 * 3600, len(df)))
    stamps = pd.Timestamp("2017-07-03 09:00") + pd.to_timedelta(offsets, unit="s")
    df[" Timestamp"] = [
        f"{t.month}/{t.day}/{t.year} {t.hour % 12 or 12}:{t.minute:02d}" for t in stamps
    ]
    df.insert(0, "Flow ID", [f"10.0.0.{i % 250}-{i}" for i in range(len(df))])
    df.insert(1, " Source IP", [f"192.168.10.{i % 250 + 1}" for i in range(len(df))])
    df.insert(2, " Source Port", rng.integers(1024, 65535, len(df)))
    df.insert(3, " Destination IP", "192.168.10.50")

    # Reproduce known data-quality problems so the cleaning path is exercised.
    inf_rows = rng.choice(len(df), size=max(1, len(df) // 500), replace=False)
    df.loc[inf_rows, "Flow Bytes/s"] = np.inf
    nan_rows = rng.choice(len(df), size=max(1, len(df) // 500), replace=False)
    df.loc[nan_rows, " Flow Packets/s"] = np.nan
    duplicates = df.sample(n=max(1, len(df) // 100), random_state=seed)
    return pd.concat([df, duplicates], ignore_index=True)
