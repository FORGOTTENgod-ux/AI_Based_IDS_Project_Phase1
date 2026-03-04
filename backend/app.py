# backend/app.py
"""
Flask backend for AI_Based_IDS_Project
- Live capture endpoints (uses backend/live_capture.py)
- Upload endpoint /upload_file that accepts .pcap/.pcapng/.csv
  -> aggregates flows, runs RF pipeline, returns percentage bar chart data + sample rows
- Serves frontend files from ../frontend
"""

import os
import time
import traceback
from flask import Flask, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename

# optional libs
try:
    import joblib
except Exception:
    joblib = None

try:
    import pandas as pd
    import numpy as np
except Exception:
    pd = None
    np = None

# local live_capture module
try:
    from live_capture import start_capture as lc_start, stop_capture as lc_stop, get_latest_packets, clear_packets
except Exception:
    # fallback no-op functions if live_capture missing
    def lc_start(*a, **k): return
    def lc_stop(*a, **k): return
    def get_latest_packets(n=200): return []
    def clear_packets(): return

THIS_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(THIS_DIR, "..", "frontend")
UPLOAD_DIR = os.path.join(THIS_DIR, "backend_uploads")
MODEL_PATHS = [
    os.path.join(os.path.dirname(THIS_DIR), "models", "rf_ids_model.joblib"),
    os.path.join(os.path.dirname(THIS_DIR), "models", "rf_ids_model.pkl"),
    os.path.join(os.path.dirname(THIS_DIR), "models", "rf_ids_model"),
]

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__, static_folder=FRONTEND_DIR, template_folder=FRONTEND_DIR)

ALLOWED_EXTS = {".pcap", ".pcapng", ".csv"}

# Load model bundle if available
MODEL_BUNDLE = None
if joblib is not None:
    for p in MODEL_PATHS:
        if os.path.exists(p):
            try:
                MODEL_BUNDLE = joblib.load(p)
                print(f"[app] Loaded model bundle from: {p}")
                break
            except Exception as e:
                print(f"[app] Failed to load model at {p}: {e}")

if MODEL_BUNDLE is None:
    print("[app] No model bundle loaded. Upload/predict endpoints will return an error until a model is available.")

###########################
# Helpers - file handling #
###########################
def allowed_file(filename):
    _, ext = os.path.splitext(filename.lower())
    return ext in ALLOWED_EXTS

def save_upload(file_storage):
    filename = secure_filename(file_storage.filename)
    dest = os.path.join(UPLOAD_DIR, f"{int(time.time())}_{filename}")
    file_storage.save(dest)
    return dest

###########################
# Packet extraction utils #
###########################
def extract_packets_from_pcap(pcap_path, max_packets=None):
    """Extract basic packet fields from pcap using pyshark (if available)."""
    if 'pyshark' not in globals():
        try:
            import pyshark
        except Exception:
            raise RuntimeError("pyshark not available. Install pyshark + tshark to parse pcap.")
    import pyshark

    packets = []
    try:
        cap = pyshark.FileCapture(pcap_path, keep_packets=False)
        for i, pkt in enumerate(cap):
            if max_packets and i >= max_packets:
                break
            try:
                ts = getattr(pkt, "sniff_time", None)
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else time.strftime("%Y-%m-%d %H:%M:%S")
                src = pkt.ip.src if hasattr(pkt, "ip") and hasattr(pkt.ip, "src") else "-"
                dst = pkt.ip.dst if hasattr(pkt, "ip") and hasattr(pkt.ip, "dst") else "-"
                proto = pkt.highest_layer if hasattr(pkt, "highest_layer") else "-"
                length = getattr(pkt, "length", 0)
                length = int(length) if str(length).isdigit() else 0
                src_port = getattr(pkt, "srcport", None) or getattr(getattr(pkt, "tcp", None), "srcport", None) or getattr(getattr(pkt, "udp", None), "srcport", None) or ""
                dst_port = getattr(pkt, "dstport", None) or getattr(getattr(pkt, "tcp", None), "dstport", None) or getattr(getattr(pkt, "udp", None), "dstport", None) or ""
                flags = ""
                if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "flags"):
                    flags = pkt.tcp.flags
                packets.append({
                    "frame.time_epoch": time.time(),
                    "ip.src": src,
                    "ip.dst": dst,
                    "frame.len": length,
                    "src_port": str(src_port),
                    "dst_port": str(dst_port),
                    "tcp.flags": str(flags)
                })
            except Exception:
                continue
        cap.close()
    except Exception as e:
        raise RuntimeError(f"Error reading pcap: {e}")
    return packets

def extract_packets_from_csv(csv_path, max_rows=None):
    """Read CSV and normalize column names to expected fields."""
    if pd is None:
        raise RuntimeError("pandas required to read CSV uploads.")
    df = pd.read_csv(csv_path, low_memory=False)
    if max_rows:
        df = df.head(max_rows)

    # Normalize columns and create expected columns if missing
    out = []
    for _, row in df.iterrows():
        try:
            ts = row.get("frame.time_epoch") if "frame.time_epoch" in row else row.get("frame.time")
            src = row.get("ip.src") if "ip.src" in row else row.get("src") if "src" in row else "-"
            dst = row.get("ip.dst") if "ip.dst" in row else row.get("dst") if "dst" in row else "-"
            length = row.get("frame.len") if "frame.len" in row else row.get("length") if "length" in row else 0
            try:
                length = int(length)
            except Exception:
                length = 0
            src_port = row.get("tcp.srcport", "") or row.get("udp.srcport", "") or row.get("src_port", "")
            dst_port = row.get("tcp.dstport", "") or row.get("udp.dstport", "") or row.get("dst_port", "")
            flags = row.get("tcp.flags", "")
            out.append({
                "frame.time_epoch": ts if ts is not None else time.time(),
                "ip.src": src,
                "ip.dst": dst,
                "frame.len": length,
                "src_port": str(src_port),
                "dst_port": str(dst_port),
                "tcp.flags": str(flags)
            })
        except Exception:
            continue
    return out

###########################################
# Aggregation: mimic aggregate_flows.py   #
###########################################
def aggregate_by_window_from_packets(packets, window_size=5):
    """
    Build a pandas DataFrame aggregated by (ip.src, ip.dst, time_bin) similar to aggregate_flows.py
    Returns DataFrame with numeric columns that model expects.
    """
    if pd is None:
        raise RuntimeError("pandas required for aggregation.")
    df = pd.DataFrame(packets)
    if df.empty:
        return pd.DataFrame()
    # ensure numeric fields exist
    for col in ["frame.len"]:
        if col not in df.columns:
            df[col] = 0
    # try to ensure time epoch numeric
    if "frame.time_epoch" in df.columns:
        try:
            df["frame.time_epoch"] = pd.to_numeric(df["frame.time_epoch"], errors="coerce").fillna(method='ffill').fillna(0)
        except Exception:
            df["frame.time_epoch"] = pd.Series(np.arange(len(df))).astype(int)
    else:
        df["frame.time_epoch"] = pd.Series(np.arange(len(df))).astype(int)

    df["time_bin"] = (df["frame.time_epoch"] // window_size).astype(int)

    # normalize ports
    for c in ["src_port", "dst_port", "tcp.flags"]:
        if c not in df.columns:
            df[c] = ""

    grouped = df.groupby(["ip.src", "ip.dst", "time_bin"])
    agg = grouped.agg(
        packet_count=("frame.len", "count"),
        total_bytes=("frame.len", "sum"),
        avg_frame_len=("frame.len", "mean"),
        min_frame_len=("frame.len", "min"),
        max_frame_len=("frame.len", "max"),
        unique_src_ports=("src_port", pd.Series.nunique),
        unique_dst_ports=("dst_port", pd.Series.nunique),
        syn_count=("tcp.flags", lambda s: sum('S' in str(x) for x in s)),
        ack_count=("tcp.flags", lambda s: sum('A' in str(x) or 'ACK' in str(x).upper() for x in s)),
        rst_count=("tcp.flags", lambda s: sum('R' in str(x) for x in s)),
        psh_count=("tcp.flags", lambda s: sum('P' in str(x) for x in s)),
    ).reset_index()

    # derived metrics
    agg["bytes_per_packet"] = (agg["total_bytes"] / agg["packet_count"]).fillna(0)
    agg["packets_per_sec"] = (agg["packet_count"] / window_size).fillna(0)
    # Ensure numeric types
    numeric_cols = [c for c in agg.columns if c not in ["ip.src","ip.dst","time_bin"]]
    agg[numeric_cols] = agg[numeric_cols].apply(pd.to_numeric, errors='coerce').fillna(0)
    return agg

####################
# Prediction util   #
####################
def run_model_on_agg_df(agg_df):
    """
    Returns dataframe with prediction & probability columns appended.
    Expects MODEL_BUNDLE format: {'pipeline': pipeline, 'label_encoder': le, 'feature_columns': [...]}
    """
    if MODEL_BUNDLE is None:
        raise RuntimeError("No model loaded on server.")

    pipeline = MODEL_BUNDLE.get("pipeline") or MODEL_BUNDLE.get("model") or MODEL_BUNDLE
    label_encoder = MODEL_BUNDLE.get("label_encoder", None)
    feature_cols = MODEL_BUNDLE.get("feature_columns", None)

    if feature_cols is None:
        # fallback: numeric columns except grouping
        feature_cols = [c for c in agg_df.columns if agg_df[c].dtype.kind in "fi"]

    # ensure columns present
    missing = [c for c in feature_cols if c not in agg_df.columns]
    if missing:
        # try to add missing as zeros
        for m in missing:
            agg_df[m] = 0

    X = agg_df[feature_cols].copy()
    # pipeline may contain preprocessing -> predict returns encoded labels
    preds_encoded = pipeline.predict(X)
    # try predict_proba
    probs = None
    try:
        probs_arr = pipeline.predict_proba(X)
        # choose max prob per row
        probs = [float(max(row)) for row in probs_arr]
    except Exception:
        probs = [None] * len(preds_encoded)

    # inverse transform preds if label encoder present and preds are encoded
    if label_encoder is not None:
        try:
            preds = label_encoder.inverse_transform(preds_encoded.astype(int))
        except Exception:
            # If pipeline already outputs labels string, use directly
            preds = preds_encoded
    else:
        preds = preds_encoded

    agg_df = agg_df.copy()
    agg_df["prediction"] = preds
    agg_df["probability"] = probs
    return agg_df

####################
# Routes           #
####################
@app.route("/")
def index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/live")
def live_page():
    return send_from_directory(FRONTEND_DIR, "live.html")

@app.route("/upload")
def upload_page():
    return send_from_directory(FRONTEND_DIR, "upload.html")

# live capture control
@app.route("/start_capture", methods=["POST"])
def start_capture_route():
    data = request.get_json() or {}
    interface = data.get("interface", "Wi-Fi")
    bpf_filter = data.get("filter", "")
    print(f"[app] Received start_capture with interface='{interface}', filter='{bpf_filter}'")
    lc_start(interface, bpf_filter)
    return jsonify({"status": "started", "interface": interface, "filter": bpf_filter})


@app.route("/stop_capture", methods=["POST"])
def stop_capture_route():
    lc_stop()
    return jsonify({"status": "stopped"})

@app.route("/clear_packets", methods=["POST"])
def clear_packets_route():
    clear_packets()
    return jsonify({"status": "cleared"})

@app.route("/live_packets", methods=["GET"])
def live_packets_route():
    n = int(request.args.get("n", 200))
    data = get_latest_packets(n)
    return jsonify(data)

# upload + predict
@app.route("/upload_file", methods=["POST"])
def upload_file_route():
    """
    Accepts a single file in 'file' field. .pcap/.pcapng/.csv allowed.
    Returns JSON:
    {
      status: "ok",
      file: "<name>",
      flows: <int>,
      percentages: {"Normal": 80.0, "DoS": 10.0, ...},
      sample: [ {..}, ... ]
    }
    """
    if MODEL_BUNDLE is None:
        return jsonify({"status":"error","message":"No ML model loaded on server."}), 500

    if 'file' not in request.files:
        return jsonify({"status":"error","message":"No file part"}), 400
    f = request.files['file']
    if f.filename == "":
        return jsonify({"status":"error","message":"No selected file"}), 400
    if not allowed_file(f.filename):
        return jsonify({"status":"error","message":"Invalid file type"}), 400

    saved = save_upload(f)
    print(f"[app] Saved upload to {saved}")
    try:
        _, ext = os.path.splitext(saved.lower())
        if ext in (".pcap", ".pcapng"):
            packets = extract_packets_from_pcap(saved, max_packets=10000)
        elif ext == ".csv":
            packets = extract_packets_from_csv(saved, max_rows=50000)
        else:
            return jsonify({"status":"error","message":"Unsupported ext"}), 400

        agg = aggregate_by_window_from_packets(packets, window_size=5)
        if agg.empty:
            return jsonify({"status":"ok","message":"No flows extracted","flows":0,"file":os.path.basename(saved)})

        pred_df = run_model_on_agg_df(agg)
        # compute percentage distribution
        counts = pred_df['prediction'].value_counts().to_dict()
        total = sum(counts.values())
        percentages = {str(k): round((v/total)*100, 2) for k,v in counts.items()} if total>0 else {}

        # prepare sample rows for frontend (first 30)
        sample = pred_df.head(30).to_dict(orient='records')

        return jsonify({
            "status": "ok",
            "file": os.path.basename(saved),
            "flows": int(len(pred_df)),
            "percentages": percentages,
            "sample": sample
        })
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status":"error","message": str(e)}), 500

# static proxy for frontend assets
@app.route("/<path:filename>")
def static_proxy(filename):
    frontend_path = os.path.join(FRONTEND_DIR, filename)
    if os.path.exists(frontend_path):
        return send_from_directory(FRONTEND_DIR, filename)
    return send_from_directory(FRONTEND_DIR, "index.html")

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
