#!/usr/bin/env python3
"""
validate_and_clean_csvs.py
----------------------------------
Validates and cleans raw CSV files (exported from tshark)
for the AI-Based Intrusion Detection System (IDS) project.

Input  : data/raw_csv/*.csv
Output : data/cleaned_csv/*_clean.csv
"""

import os
import argparse
import pandas as pd
import numpy as np

# ------------------ Required Columns ------------------
REQUIRED = ['frame.time_epoch', 'ip.src', 'ip.dst', 'frame.len']

# ------------------ Helper Functions ------------------
def parse_tcp_flags_to_int(val):
    """Convert hex or string TCP flag values to integer."""
    if pd.isna(val) or str(val).strip() == '':
        return np.nan
    s = str(val).strip()
    if s.lower().startswith('0x'):
        try:
            return int(s, 16)
        except ValueError:
            return np.nan
    try:
        return int(s)
    except ValueError:
        return np.nan


def flags_from_int(n):
    """Decode TCP flag bits into separate columns."""
    if np.isnan(n):
        return {'flag_fin': 0, 'flag_syn': 0, 'flag_rst': 0,
                'flag_psh': 0, 'flag_ack': 0, 'flag_urg': 0}
    n = int(n)
    return {
        'flag_fin': 1 if (n & 0x01) else 0,
        'flag_syn': 1 if (n & 0x02) else 0,
        'flag_rst': 1 if (n & 0x04) else 0,
        'flag_psh': 1 if (n & 0x08) else 0,
        'flag_ack': 1 if (n & 0x10) else 0,
        'flag_urg': 1 if (n & 0x20) else 0
    }


def clean_df(df, filename):
    """Clean a single DataFrame and return cleaned version + report."""
    report = {"filename": filename, "original_shape": df.shape}

    # Check for required columns
    missing = [c for c in REQUIRED if c not in df.columns]
    report['missing_required'] = missing

    # Convert time and length to numeric
    if 'frame.time_epoch' in df.columns:
        df['frame.time_epoch'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')
    if 'frame.len' in df.columns:
        df['frame.len'] = pd.to_numeric(df['frame.len'], errors='coerce')

    # Clean ports (TCP + UDP)
    for col in ['tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0).astype(int)
        else:
            df[col] = 0

    df['src_port'] = df['tcp.srcport'].where(df['tcp.srcport'] != 0, df['udp.srcport'])
    df['dst_port'] = df['tcp.dstport'].where(df['tcp.dstport'] != 0, df['udp.dstport'])

    # Parse TCP flags
    if 'tcp.flags' in df.columns:
        df['tcp.flags.int'] = df['tcp.flags'].apply(parse_tcp_flags_to_int).fillna(0).astype(int)
    else:
        df['tcp.flags.int'] = 0

    flag_cols = df['tcp.flags.int'].apply(flags_from_int).apply(pd.Series)
    df = pd.concat([df, flag_cols], axis=1)

    # Add HTTP columns if missing
    for h in ['http.request.method', 'http.request.uri', 'http.host', 'data.text']:
        if h not in df.columns:
            df[h] = ''

    # Drop rows missing essential fields
    before = df.shape[0]
    df = df.dropna(subset=['frame.time_epoch', 'frame.len'])
    after = df.shape[0]
    report['dropped_rows'] = before - after

    # Sort by time
    df = df.sort_values('frame.time_epoch').reset_index(drop=True)

    # Fill missing numerics with 0
    for col in df.select_dtypes(include=[np.number]).columns:
        df[col] = df[col].fillna(0)

    report['final_shape'] = df.shape
    return df, report

# ------------------ Main Script ------------------
def main(input_dir, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    summary = []

    csv_files = [f for f in os.listdir(input_dir) if f.endswith('.csv')]
    if not csv_files:
        print(f"[!] No CSV files found in {input_dir}")
        return

    for filename in csv_files:
        file_path = os.path.join(input_dir, filename)
        print(f"[INFO] Processing: {filename}")
        try:
            df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
            cleaned_df, report = clean_df(df, filename)

            out_name = filename.replace('.csv', '_clean.csv')
            out_path = os.path.join(output_dir, out_name)
            cleaned_df.to_csv(out_path, index=False)

            print(f"  ✅ Cleaned -> {out_path} | {cleaned_df.shape[0]} rows")
            summary.append(report)
        except Exception as e:
            print(f"  ❌ Error processing {filename}: {e}")

    print("\n=== Summary Report ===")
    for r in summary:
        print(f"\nFile: {r['filename']}")
        print(f" Original shape : {r['original_shape']}")
        print(f" Missing columns: {r['missing_required']}")
        print(f" Rows dropped   : {r['dropped_rows']}")
        print(f" Final shape    : {r['final_shape']}")
    print("\n✅ Cleaning completed successfully.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Validate and clean tshark CSV files.")
    parser.add_argument("--in-dir", default="data/raw_csv", help="Input directory containing raw CSV files")
    parser.add_argument("--out-dir", default="data/cleaned_csv", help="Output directory for cleaned CSVs")
    args = parser.parse_args()

    main(args.in_dir, args.out_dir)
