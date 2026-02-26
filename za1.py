#!/usr/bin/env python3
"""
analyze_metrics.py
Extracts PDR, E2E Delay, Jitter, Throughput from:
  1. app-layer-stats.csv
  2. *-flowmon.xml  (FlowMonitor IP layer)
  3. *.pcap         (L2 PCAP)
"""

import os
import re
import sys
import glob
import xml.etree.ElementTree as ET
from collections import defaultdict

import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# ─────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────
APP_LOG_CSV    = "app-layer-stats.csv"
OUTPUT_PREFIX  = "manet-run"
FLOWMON_GLOB   = OUTPUT_PREFIX + "-run*-flowmon.xml"
PCAP_GLOB      = OUTPUT_PREFIX + "-run*.pcap"
OUTPUT_CSV     = "metrics_combined.csv"
PLOT_DIR       = "plots"

APP_START      = 1.0
APP_STOP       = 29.0
UDP_DST_PORT   = 9
PKT_SIZE_BYTES = 512

# ─────────────────────────────────────────────────────────────
# NOTE ON COLUMN NAMES: no '%' anywhere – pandas groupby named
# aggregation can silently drop columns with special characters
# in older versions.  Use _pct suffix everywhere.
# ─────────────────────────────────────────────────────────────

# =============================================================
# LAYER 1 – App-layer CSV
# =============================================================

def load_app_csv(path):
    if not os.path.exists(path):
        print("[WARN] App CSV not found: " + path)
        return pd.DataFrame()
    df = pd.read_csv(path)
    df.columns = [c.strip() for c in df.columns]
    # Rename % column immediately
    df = df.rename(columns={"PDR%": "App_PDR_pct",
                             "AppDelay_ms":  "App_Delay_ms",
                             "AppJitter_ms": "App_Jitter_ms",
                             "AppTput_kbps": "App_Tput_kbps"})
    return df


# =============================================================
# LAYER 2 – FlowMonitor XML
# =============================================================

def parse_ns3_time(s):
    s = s.strip().lstrip("+")
    if s.endswith("ns"): return float(s[:-2]) * 1e-9
    if s.endswith("us"): return float(s[:-2]) * 1e-6
    if s.endswith("ms"): return float(s[:-2]) * 1e-3
    if s.endswith("s"):  return float(s[:-1])
    return float(s)


def parse_flowmon_xml(xml_path, run_id):
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError as e:
        print("[WARN] Cannot parse " + xml_path + ": " + str(e))
        return []

    root = tree.getroot()

    # ── Classifier: <Ipv4FlowClassifier><Flow .../></Ipv4FlowClassifier>
    flow_info = {}
    clf = root.find("Ipv4FlowClassifier")
    if clf is not None:
        for cls in clf.findall("Flow"):
            fid = int(cls.attrib.get("flowId", -1))
            flow_info[fid] = {
                "src":   cls.attrib.get("sourceAddress",      ""),
                "dst":   cls.attrib.get("destinationAddress", ""),
                "sport": cls.attrib.get("sourcePort",         ""),
                "dport": cls.attrib.get("destinationPort",    ""),
            }
    print("    Classifier flows found: " + str(len(flow_info)))

    # ── Stats: <FlowStats><Flow .../></FlowStats>
    rows = []
    sc = root.find("FlowStats")
    if sc is None:
        print("[WARN] No <FlowStats> in " + xml_path)
        return rows

    all_flows = sc.findall("Flow")
    print("    Stats flows found: " + str(len(all_flows)))

    for fs in all_flows:
        fid      = int(fs.attrib.get("flowId",      -1))
        tx_pkts  = int(fs.attrib.get("txPackets",    0))
        rx_pkts  = int(fs.attrib.get("rxPackets",    0))
        rx_bytes = int(fs.attrib.get("rxBytes",      0))
        lost     = int(fs.attrib.get("lostPackets",  0))

        info  = flow_info.get(fid, {})
        dport = int(info.get("dport", 0)) if info.get("dport", "") != "" else 0

        # Debug: print every flow so user can see what is present
        print("      fid=" + str(fid) +
              " dport=" + str(dport) +
              " tx=" + str(tx_pkts) +
              " rx=" + str(rx_pkts) +
              " rxB=" + str(rx_bytes))

        # Keep only the data flow (UDP port 9)
        if dport != UDP_DST_PORT:
            continue

        delay_sum  = parse_ns3_time(fs.attrib.get("delaySum",  "0s"))
        jitter_sum = parse_ns3_time(fs.attrib.get("jitterSum", "0s"))

        pdr        = (rx_pkts / tx_pkts * 100.0)           if tx_pkts > 0 else 0.0
        avg_delay  = (delay_sum  / rx_pkts * 1000.0)        if rx_pkts > 0 else 0.0
        avg_jitter = (jitter_sum / max(rx_pkts-1,1) * 1000.0) if rx_pkts > 1 else 0.0

        t_first  = parse_ns3_time(fs.attrib.get("timeFirstTxPacket", "0s"))
        t_last   = parse_ns3_time(fs.attrib.get("timeLastRxPacket",  "0s"))
        duration = t_last - t_first
        if duration <= 0:
            duration = APP_STOP - APP_START
        tput_kbps = (rx_bytes * 8.0 / duration / 1000.0) if duration > 0 else 0.0

        print("      -> KEPT  pdr=" + str(round(pdr,2)) +
              " delay=" + str(round(avg_delay,3)) +
              " jitter=" + str(round(avg_jitter,3)) +
              " tput=" + str(round(tput_kbps,3)))

        rows.append({
            "RunID":         run_id,
            "FlowID":        fid,
            "FM_Src":        info.get("src", ""),
            "FM_Dst":        info.get("dst", ""),
            "FM_TxPkts":     tx_pkts,
            "FM_RxPkts":     rx_pkts,
            "FM_Lost":       lost,
            "FM_PDR_pct":    round(pdr,        2),
            "FM_Delay_ms":   round(avg_delay,  3),
            "FM_Jitter_ms":  round(avg_jitter, 3),
            "FM_Tput_kbps":  round(tput_kbps,  3),
        })
    return rows


def load_all_flowmon(glob_pat):
    files = sorted(glob.glob(glob_pat))
    if not files:
        print("[WARN] No FlowMonitor XML matching: " + glob_pat)
        return pd.DataFrame()

    all_rows = []
    for f in files:
        m = re.search(r"run(\d+)", f)
        rid = int(m.group(1)) if m else -1
        print("  Parsing: " + f)
        all_rows.extend(parse_flowmon_xml(f, rid))

    return pd.DataFrame(all_rows) if all_rows else pd.DataFrame()


# =============================================================
# LAYER 3 – PCAP (scapy)
# =============================================================

def analyze_pcap_run(pcap_files, run_id):
    try:
        from scapy.all import rdpcap, UDP, IP, Raw
    except ImportError:
        print("[WARN] scapy not installed. pip install scapy")
        return {}

    tx_map    = {}
    rx_set    = set()
    rx_delays = []

    for pf in pcap_files:
        try:
            pkts = rdpcap(pf)
        except Exception as e:
            print("[WARN] Cannot read " + pf + ": " + str(e))
            continue
        for pkt in pkts:
            if IP not in pkt or UDP not in pkt:
                continue
            if int(pkt[UDP].dport) != UDP_DST_PORT:
                continue
            ts  = float(pkt.time)
            if not (APP_START <= ts <= APP_STOP + 1.0):
                continue
            raw = bytes(pkt[UDP].payload) if Raw in pkt else b""
            if len(raw) < 12:
                continue
            seq = int.from_bytes(raw[0:4], "big")
            if seq not in tx_map:
                tx_map[seq] = ts
            elif seq not in rx_set:
                rx_set.add(seq)
                d = ts - tx_map[seq]
                if d >= 0:
                    rx_delays.append(d)

    tx_pkts = len(tx_map)
    rx_pkts = len(rx_set)
    pdr     = (rx_pkts / tx_pkts * 100.0) if tx_pkts > 0 else 0.0
    avg_d   = (sum(rx_delays) / len(rx_delays) * 1000.0) if rx_delays else 0.0
    jits    = [abs(rx_delays[i]-rx_delays[i-1]) for i in range(1,len(rx_delays))]
    avg_j   = (sum(jits) / len(jits) * 1000.0) if jits else 0.0
    dur     = APP_STOP - APP_START
    tput    = (rx_pkts * PKT_SIZE_BYTES * 8.0 / dur / 1000.0) if dur > 0 else 0.0

    return {
        "RunID":          run_id,
        "PCAP_TxPkts":    tx_pkts,
        "PCAP_RxPkts":    rx_pkts,
        "PCAP_PDR_pct":   round(pdr,   2),
        "PCAP_Delay_ms":  round(avg_d, 3),
        "PCAP_Jitter_ms": round(avg_j, 3),
        "PCAP_Tput_kbps": round(tput,  3),
    }


def load_all_pcap(glob_pat):
    files = sorted(glob.glob(glob_pat))
    if not files:
        print("[WARN] No PCAP files matching: " + glob_pat)
        return pd.DataFrame()

    run_files = defaultdict(list)
    for f in files:
        m = re.search(r"run(\d+)", f)
        rid = int(m.group(1)) if m else -1
        run_files[rid].append(f)

    rows = []
    for rid in sorted(run_files.keys()):
        print("  PCAP run " + str(rid) + ": " + str(len(run_files[rid])) + " files")
        row = analyze_pcap_run(run_files[rid], rid)
        if row:
            rows.append(row)
    return pd.DataFrame(rows) if rows else pd.DataFrame()


# =============================================================
# MERGE
# =============================================================

def merge_all(app_df, fm_df, pc_df):
    # App layer
    base = app_df.copy() if not app_df.empty else pd.DataFrame()

    # FlowMonitor aggregate per run – avoid % in column names
    if not fm_df.empty:
        # Use dict-based agg (compatible with all pandas versions)
        agg_dict = {
            "FM_TxPkts":    "sum",
            "FM_RxPkts":    "sum",
            "FM_PDR_pct":   "mean",
            "FM_Delay_ms":  "mean",
            "FM_Jitter_ms": "mean",
            "FM_Tput_kbps": "sum",
        }
        # Only agg columns that exist
        agg_dict = {k: v for k, v in agg_dict.items() if k in fm_df.columns}
        fm_agg = fm_df.groupby("RunID").agg(agg_dict).reset_index()
    else:
        fm_agg = pd.DataFrame()

    if base.empty and fm_agg.empty and pc_df.empty:
        print("[ERROR] No data from any layer.")
        sys.exit(1)

    merged = base
    if not fm_agg.empty:
        if merged.empty:
            merged = fm_agg
        else:
            merged = merged.merge(fm_agg, on="RunID", how="outer")
    if not pc_df.empty:
        if merged.empty:
            merged = pc_df
        else:
            merged = merged.merge(pc_df, on="RunID", how="outer")

    return merged.sort_values("RunID").reset_index(drop=True)


# =============================================================
# PLOT
# =============================================================

# suffix must match column names: App_{suffix}, FM_{suffix}, PCAP_{suffix}
METRICS = [
    ("PDR_pct",   "Packet Delivery Ratio", "PDR (%)"),
    ("Delay_ms",  "End-to-End Delay",      "Delay (ms)"),
    ("Jitter_ms", "Jitter",                "Jitter (ms)"),
    ("Tput_kbps", "Throughput",            "Throughput (kbps)"),
]

LAYERS = [
    ("App_",  "App Layer",        "tab:blue",   "o",  2.5, "-"),
    ("FM_",   "FlowMonitor (IP)", "tab:orange",  "s",  1.5, "--"),
    ("PCAP_", "PCAP (L2)",        "tab:green",  "^",  1.5, "-."),
]


def plot_metrics(df, x_col, x_label, plot_dir):
    os.makedirs(plot_dir, exist_ok=True)

    for suffix, title, ylabel in METRICS:
        fig, ax = plt.subplots(figsize=(8, 5))
        plotted = False

        for prefix, name, color, marker, lw, ls in LAYERS:
            col = prefix + suffix
            if col not in df.columns:
                print("  [PLOT] column not found: " + col)
                continue
            sub = df[[x_col, col]].dropna()
            if sub.empty:
                print("  [PLOT] all NaN for: " + col)
                continue
            print("  [PLOT] " + col + " -> " + str(sub[col].tolist()))
            ax.plot(sub[x_col], sub[col],
                    label=name, color=color,
                    marker=marker, linewidth=lw,
                    markersize=8, linestyle=ls,
                    zorder=10 if prefix == "App_" else 5)
            plotted = True

        if not plotted:
            plt.close(fig)
            continue

        ax.set_title(title, fontsize=14, fontweight="bold")
        ax.set_xlabel(x_label, fontsize=12)
        ax.set_ylabel(ylabel,  fontsize=12)
        ax.legend(fontsize=11)
        ax.grid(True, linestyle="--", alpha=0.5)
        plt.tight_layout()

        out = os.path.join(plot_dir, suffix + ".png")
        fig.savefig(out, dpi=150)
        plt.close(fig)
        print("  Saved -> " + out)


def auto_x_axis(df):
    for col, label in [("NumNodes", "Number of Nodes"),
                       ("Gap",      "Inter-node Gap (m)"),
                       ("RunID",    "Run ID")]:
        if col in df.columns and df[col].nunique() > 1:
            return col, label
    return "RunID", "Run ID"


# =============================================================
# SUMMARY
# =============================================================

def print_summary(df):
    print("\n" + "=" * 110)
    print("  MERGED DATAFRAME – ALL COLUMNS AND VALUES")
    print("=" * 110)
    pd.set_option("display.max_columns", None)
    pd.set_option("display.width",       220)
    pd.set_option("display.float_format", "{:.3f}".format)
    print(df.to_string(index=False))
    print("=" * 110)
    print("\nColumns present: " + str(list(df.columns)))


# =============================================================
# MAIN
# =============================================================

def main():
    print("\n# Layer 1: App-layer CSV")
    app_df = load_app_csv(APP_LOG_CSV)
    print("  Rows: " + str(len(app_df)))

    print("\n# Layer 2: FlowMonitor XML")
    fm_df = load_all_flowmon(FLOWMON_GLOB)
    print("  Flow records kept: " + str(len(fm_df)))

    print("\n# Layer 3: PCAP")
    pc_df = load_all_pcap(PCAP_GLOB)
    print("  Runs processed: " + str(len(pc_df)))

    print("\n# Merging")
    merged = merge_all(app_df, fm_df, pc_df)
    merged.to_csv(OUTPUT_CSV, index=False)
    print("  Saved -> " + OUTPUT_CSV)

    print_summary(merged)

    print("\n# Plots")
    x_col, x_label = auto_x_axis(merged)
    plot_metrics(merged, x_col, x_label, PLOT_DIR)

    if not fm_df.empty:
        detail = os.path.join(PLOT_DIR, "flowmon_per_flow.csv")
        fm_df.to_csv(detail, index=False)
        print("  Per-flow detail -> " + detail)

    print("\nDone.")


if __name__ == "__main__":
    main()
