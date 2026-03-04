#!/usr/bin/env python3
"""
aggregate_flows.py
-------------------------
Aggregates cleaned per-packet CSVs into
flow-level or time-window-level features for ML training.

Input  : data/cleaned_csv/*.csv
Output : data/aggregated_csv/aggregated_dataset.csv
"""

import os
import argparse
import pandas as pd
import numpy as np


def load_and_label_csv(path, label):
    """Load cleaned CSV and add attack label."""
    df = pd.read_csv(path)

    # Ensure numeric fields exist
    for col in ["frame.len", "src_port", "dst_port"]:
        if col not in df.columns:
            df[col] = 0
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # Ensure TCP flag columns exist
    for f in ["flag_syn", "flag_ack", "flag_rst", "flag_psh"]:
        if f not in df.columns:
            df[f] = 0

    # Ensure timestamp column exists
    if "frame.time_epoch" not in df.columns:
        raise ValueError(f"Missing 'frame.time_epoch' in {path}")
    df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce").fillna(0)

    df["label"] = label
    return df


def aggregate_by_window(df, window_size=5):
    """Aggregate per flow/time window."""
    # Create time bins
    df["time_bin"] = (df["frame.time_epoch"] // window_size).astype(int)

    grouped = df.groupby(["ip.src", "ip.dst", "time_bin"])

    # Aggregate statistics safely
    agg = grouped.agg(
        packet_count=("frame.len", "count"),
        total_bytes=("frame.len", "sum"),
        avg_frame_len=("frame.len", "mean"),
        min_frame_len=("frame.len", "min"),
        max_frame_len=("frame.len", "max"),
        unique_src_ports=("src_port", pd.Series.nunique),
        unique_dst_ports=("dst_port", pd.Series.nunique),
        syn_count=("flag_syn", "sum"),
        ack_count=("flag_ack", "sum"),
        rst_count=("flag_rst", "sum"),
        psh_count=("flag_psh", "sum"),
    ).reset_index()

    # Derived metrics
    agg["bytes_per_packet"] = (agg["total_bytes"] / agg["packet_count"]).fillna(0)
    agg["packets_per_sec"] = (agg["packet_count"] / window_size).fillna(0)

    return agg


def main(input_dir, output_path, window_size):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    label_map = {
        "normal": "Normal",
        "dos": "DoS",
        "scan": "Scan",
        "sqlmap": "SQLi",
        "sqlinjection": "SQLi"
    }

    combined = []
    csv_files = [f for f in os.listdir(input_dir) if f.endswith(".csv")]

    if not csv_files:
        print(f"[!] No CSV files found in {input_dir}")
        return

    for f in csv_files:
        label_key = next((k for k in label_map.keys() if k in f.lower()), "Unknown")
        label = label_map.get(label_key, "Unknown")
        path = os.path.join(input_dir, f)

        print(f"[INFO] Aggregating {f} → Label: {label}")

        try:
            df = load_and_label_csv(path, label)
            if len(df) == 0:
                print(f"  ⚠️ Skipping {f} (empty or invalid data)")
                continue

            agg = aggregate_by_window(df, window_size)
            agg["label"] = label
            combined.append(agg)

        except Exception as e:
            print(f"  ❌ Error processing {f}: {e}")

    if not combined:
        print("[!] No valid data aggregated. Exiting.")
        return

    final_df = pd.concat(combined, ignore_index=True)
    final_df = final_df.dropna().reset_index(drop=True)

    final_df.to_csv(output_path, index=False)
    print(f"\n✅ Aggregation complete! Saved → {os.path.abspath(output_path)}")
    print(f"   Total samples: {len(final_df)}")
    print(f"   Columns: {list(final_df.columns)}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Aggregate cleaned CSVs into flow-based dataset for ML.")
    parser.add_argument("--in-dir", default="data/cleaned_csv", help="Input directory of cleaned CSVs")
    parser.add_argument("--out", default="data/aggregated_csv/aggregated_dataset.csv", help="Output aggregated CSV path")
    parser.add_argument("--window", type=int, default=5, help="Aggregation window in seconds (default 5s)")
    args = parser.parse_args()

    main(args.in_dir, args.out, args.window)
