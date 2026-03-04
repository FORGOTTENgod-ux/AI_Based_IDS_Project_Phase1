# backend/live_capture.py
"""
Live packet capture using pyshark, with thread-safe buffering and robust event-loop handling.
Accepts bpf_filter strings such as:
  ip.addr==185.230.63.171
  tcp port 80 and ip.addr==192.168.1.5
"""

import pyshark
import threading
import asyncio
import time
import shutil
from collections import deque

# Global buffer of recent packets
packet_buffer = deque(maxlen=1200)
_capture_thread = None
_capture_running = False
_capture_lock = threading.Lock()


def _capture_loop(interface="Wi-Fi", bpf_filter=None):
    """
    Background capture loop running inside a separate thread.
    """
    global _capture_running, packet_buffer
    print(f"[live_capture] Capture loop starting on interface='{interface}' filter='{bpf_filter}'")

    # 1) Verify tshark exists on PATH
    tshark_path = shutil.which("tshark")
    if not tshark_path:
        print("[live_capture] ERROR: TShark not found in PATH. Install Wireshark/TShark and ensure 'tshark' is on PATH.")
        return
    print(f"[live_capture] Using tshark: {tshark_path}")

    # 2) Create and set an asyncio event loop for this thread (required by pyshark)
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    except Exception as e:
        print(f"[live_capture] Failed to create asyncio loop: {e}")
        return

    # 3) Start LiveCapture bound to this loop (explicit eventloop arg more reliable)
    try:
        # Convert Wireshark-style filters (ip.addr==) to BPF syntax if needed
        final_filter = bpf_filter
        if bpf_filter and "ip.addr" in bpf_filter:
            # Example: ip.addr==185.230.63.171 → host 185.230.63.171
            final_filter = bpf_filter.replace("ip.addr==", "host ").replace("ip.addr =", "host ")

        print(f"[live_capture] Applied filter: {final_filter}")
        capture = pyshark.LiveCapture(interface=interface, bpf_filter=final_filter, eventloop=loop)

    except Exception as e:
        print(f"[live_capture] LiveCapture initialization failed: {e}")
        try:
            loop.stop()
            loop.close()
        except Exception:
            pass
        return

    # 4) Sniff continuously and append parsed summaries to packet_buffer
    try:
        for pkt in capture.sniff_continuously():
            if not _capture_running:
                break
            try:
                ts = getattr(pkt, "sniff_time", None)
                ts_str = ts.strftime("%Y-%m-%d %H:%M:%S") if ts else time.strftime("%Y-%m-%d %H:%M:%S")

                src = "-"
                dst = "-"
                if hasattr(pkt, "ip"):
                    src = getattr(pkt.ip, "src", "-")
                    dst = getattr(pkt.ip, "dst", "-")

                proto = getattr(pkt, "highest_layer", None) or getattr(pkt, "transport_layer", None) or "-"
                length = getattr(pkt, "length", None) or getattr(getattr(pkt, "frame_info", None), "len", 0)
                length = int(length) if str(length).isdigit() else 0

                # port/flags extraction tolerant to missing layers
                src_port = (
                    getattr(pkt, "srcport", None)
                    or getattr(getattr(pkt, "tcp", None), "srcport", None)
                    or getattr(getattr(pkt, "udp", None), "srcport", None)
                    or ""
                )
                dst_port = (
                    getattr(pkt, "dstport", None)
                    or getattr(getattr(pkt, "tcp", None), "dstport", None)
                    or getattr(getattr(pkt, "udp", None), "dstport", None)
                    or ""
                )
                flags = ""
                if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "flags"):
                    flags = getattr(pkt.tcp, "flags", "")

                packet_buffer.append({
                    "timestamp": ts_str,
                    "src_ip": str(src),
                    "dst_ip": str(dst),
                    "protocol": str(proto),
                    "length": int(length),
                    "src_port": str(src_port),
                    "dst_port": str(dst_port),
                    "flags": str(flags)
                })
            except Exception as inner:
                # keep capture running even if a packet fails parsing
                print(f"[live_capture] packet parse error: {inner}")
                continue
    except Exception as e:
        print(f"[live_capture] capture runtime error: {e}")
    finally:
        # cleanup event loop
        try:
            loop.stop()
            loop.close()
        except Exception:
            pass
        print("[live_capture] capture loop ended")


def start_capture(interface="Wi-Fi", bpf_filter=None):
    """
    Start the background capture thread.
    interface: exact interface name (use `tshark -D` to list)
    bpf_filter: BPF/display filter string such as "ip.addr==1.2.3.4" or "tcp port 80"
    """
    global _capture_thread, _capture_running
    with _capture_lock:
        if _capture_thread and _capture_thread.is_alive():
            print("[live_capture] Capture already running.")
            return
        _capture_running = True
        _capture_thread = threading.Thread(target=_capture_loop, args=(interface, bpf_filter), daemon=True)
        _capture_thread.start()
        print(f"[live_capture] Started capture thread (interface='{interface}', filter='{bpf_filter}')")


def stop_capture():
    """
    Stop the live capture.
    """
    global _capture_running
    _capture_running = False
    print("[live_capture] Stop signal sent to capture loop.")


def get_latest_packets(n=200):
    """
    Return up to 'n' most recent packets as a list of dicts.
    """
    return list(packet_buffer)[-n:]


def clear_packets():
    """
    Clear the live capture packet buffer.
    """
    packet_buffer.clear()
    print("[live_capture] Cleared packet buffer.")
