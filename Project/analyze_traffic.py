"""
analyze_traffic.py

Reads a .pcap capture, extracts per-packet flow information using Scapy,
aggregates it, and applies threshold-based rules to flag anomalous
behaviour: port scans, SYN floods, and high-volume bursts from a single
source (e.g. amplification-style floods).


Run:
    python3 analyze_traffic.py sample_data/sample_capture.pcap
"""

import sys
from collections import defaultdict

from scapy.all import IP, TCP, UDP, rdpcap

import db

# ---------------------------------------------------------------------------
# Detection thresholds — tune these based on your environment's normal
# traffic baseline. Kept as simple constants so they're easy to explain
# and justify in an interview.
# ---------------------------------------------------------------------------
PORT_SCAN_WINDOW_SECONDS = 5          # look at activity in rolling 5s windows
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 15  # 15+ distinct dest ports from one src -> scan

SYN_FLOOD_WINDOW_SECONDS = 5
SYN_FLOOD_COUNT_THRESHOLD = 100       # 100+ unanswered SYNs in 5s from one src -> flood

VOLUME_WINDOW_SECONDS = 5
VOLUME_PACKET_THRESHOLD = 150         # 150+ packets to one dst in 5s from one src -> volumetric


def extract_records(packets):
    """Turn raw Scapy packets into a simple list of flow records."""
    records = []
    for pkt in packets:
        if IP not in pkt:
            continue
        ts = float(pkt.time)
        src = pkt[IP].src
        dst = pkt[IP].dst

        if TCP in pkt:
            proto = "TCP"
            dport = pkt[TCP].dport
            flags = str(pkt[TCP].flags)
        elif UDP in pkt:
            proto = "UDP"
            dport = pkt[UDP].dport
            flags = ""
        else:
            continue

        records.append(
            {"ts": ts, "src": src, "dst": dst, "dport": dport, "proto": proto, "flags": flags}
        )
    records.sort(key=lambda r: r["ts"])
    return records


def build_flow_summary(records):
    """Aggregate records into (src, dst, proto) flow summaries for display."""
    flows = defaultdict(lambda: {"count": 0, "first": None, "last": None})
    for r in records:
        key = (r["src"], r["dst"], r["proto"])
        f = flows[key]
        f["count"] += 1
        f["first"] = r["ts"] if f["first"] is None else min(f["first"], r["ts"])
        f["last"] = r["ts"] if f["last"] is None else max(f["last"], r["ts"])
    return flows


def sliding_window_counts(events_by_src, window_seconds):
    """
    Given {src: [sorted timestamps]}, yield (src, window_start, count) for
    every point where the count of events within `window_seconds` changes,
    using a simple two-pointer sliding window per source.
    """
    results = []
    for src, timestamps in events_by_src.items():
        timestamps = sorted(timestamps)
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window_seconds:
                left += 1
            count = right - left + 1
            results.append((src, timestamps[left], timestamps[right], count))
    return results


def detect_port_scans(records):
    """Flag sources that contact an unusually high number of distinct ports
    on the same destination within a short window."""
    anomalies = []
    # Group timestamps per (src, dst) -> set of distinct ports seen so far
    by_src_dst = defaultdict(list)  # (src,dst) -> [(ts, dport)]
    for r in records:
        if r["proto"] == "TCP" and "S" in r["flags"] and "A" not in r["flags"]:
            by_src_dst[(r["src"], r["dst"])].append((r["ts"], r["dport"]))

    for (src, dst), events in by_src_dst.items():
        events.sort()
        left = 0
        seen_ports = {}
        for right in range(len(events)):
            ts, port = events[right]
            while ts - events[left][0] > PORT_SCAN_WINDOW_SECONDS:
                left += 1
            window_ports = {p for (_, p) in events[left:right + 1]}
            if len(window_ports) >= PORT_SCAN_UNIQUE_PORT_THRESHOLD:
                anomalies.append(
                    {
                        "ts": ts,
                        "src": src,
                        "dst": dst,
                        "type": "Port Scan",
                        "detail": (
                            f"{len(window_ports)} distinct destination ports contacted "
                            f"within {PORT_SCAN_WINDOW_SECONDS}s (SYN-only, handshake never completed)"
                        ),
                        "severity": "High",
                    }
                )
                break  # one flag per (src,dst) pair is enough for the demo

    return anomalies


def detect_syn_floods(records):
    """Flag sources sending a very high rate of SYN-only packets to one
    destination — classic SYN flood / protocol-level DoS pattern."""
    anomalies = []
    by_src_dst = defaultdict(list)
    for r in records:
        if r["proto"] == "TCP" and "S" in r["flags"] and "A" not in r["flags"]:
            by_src_dst[(r["src"], r["dst"])].append(r["ts"])

    for (src, dst), timestamps in by_src_dst.items():
        timestamps.sort()
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > SYN_FLOOD_WINDOW_SECONDS:
                left += 1
            count = right - left + 1
            if count >= SYN_FLOOD_COUNT_THRESHOLD:
                anomalies.append(
                    {
                        "ts": timestamps[right],
                        "src": src,
                        "dst": dst,
                        "type": "SYN Flood",
                        "detail": (
                            f"{count} unanswered SYN packets within {SYN_FLOOD_WINDOW_SECONDS}s "
                            "— handshake never completed (protocol-level DoS pattern)"
                        ),
                        "severity": "Critical",
                    }
                )
                break

    return anomalies


def detect_volumetric_bursts(records):
    """Flag any single destination receiving an unusually high packet rate
    from one or more sources in a short window (volumetric/amplification-style)."""
    anomalies = []
    by_src_dst = defaultdict(list)
    for r in records:
        by_src_dst[(r["src"], r["dst"])].append(r["ts"])

    for (src, dst), timestamps in by_src_dst.items():
        timestamps.sort()
        left = 0
        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > VOLUME_WINDOW_SECONDS:
                left += 1
            count = right - left + 1
            if count >= VOLUME_PACKET_THRESHOLD:
                anomalies.append(
                    {
                        "ts": timestamps[right],
                        "src": src,
                        "dst": dst,
                        "type": "Volumetric Spike",
                        "detail": (
                            f"{count} packets from this source within {VOLUME_WINDOW_SECONDS}s "
                            "— well above normal baseline traffic rate"
                        ),
                        "severity": "High",
                    }
                )
                break

    return anomalies


DISTRIBUTED_WINDOW_SECONDS = 5
DISTRIBUTED_SOURCE_THRESHOLD = 8      # 8+ distinct sources hitting one dst
DISTRIBUTED_PACKET_THRESHOLD = 200    # with 200+ combined packets in the window


def detect_distributed_bursts(records):
    """Flag a single destination receiving a high-volume burst from MANY
    distinct sources at once — the signature of a distributed/amplification
    style attack (e.g. DNS amplification), where no single source looks
    anomalous on its own but the combined traffic to the victim is."""
    anomalies = []
    by_dst = defaultdict(list)  # dst -> [(ts, src)]
    for r in records:
        by_dst[r["dst"]].append((r["ts"], r["src"]))

    for dst, events in by_dst.items():
        events.sort()
        left = 0
        for right in range(len(events)):
            ts, _ = events[right]
            while ts - events[left][0] > DISTRIBUTED_WINDOW_SECONDS:
                left += 1
            window = events[left:right + 1]
            distinct_sources = {s for (_, s) in window}
            if len(window) >= DISTRIBUTED_PACKET_THRESHOLD and len(distinct_sources) >= DISTRIBUTED_SOURCE_THRESHOLD:
                anomalies.append(
                    {
                        "ts": ts,
                        "src": f"{len(distinct_sources)} distinct sources",
                        "dst": dst,
                        "type": "Distributed Volumetric (Amplification-style)",
                        "detail": (
                            f"{len(window)} packets from {len(distinct_sources)} different source IPs "
                            f"converged on this host within {DISTRIBUTED_WINDOW_SECONDS}s — "
                            "consistent with a reflection/amplification DDoS pattern"
                        ),
                        "severity": "Critical",
                    }
                )
                break

    return anomalies


def run_analysis(pcap_path):
    print(f"Reading packets from {pcap_path} ...")
    packets = rdpcap(pcap_path)
    print(f"Loaded {len(packets)} packets.")

    records = extract_records(packets)
    print(f"Extracted {len(records)} IP-layer flow records.")

    flows = build_flow_summary(records)
    port_scans = detect_port_scans(records)
    syn_floods = detect_syn_floods(records)
    volumetric = detect_volumetric_bursts(records)
    distributed = detect_distributed_bursts(records)

    all_anomalies = port_scans + syn_floods + volumetric + distributed
    all_anomalies.sort(key=lambda a: a["ts"])

    # Persist everything to SQLite
    db.init_db()
    conn = db.get_connection()
    for (src, dst, proto), stats in flows.items():
        db.insert_flow(conn, src, dst, proto, stats["count"], stats["first"], stats["last"])
    for a in all_anomalies:
        db.insert_anomaly(conn, a["ts"], a["src"], a["dst"], a["type"], a["detail"], a["severity"])
    conn.commit()
    conn.close()

    print(f"\nDetected {len(all_anomalies)} anomalies:")
    for a in all_anomalies:
        print(f"  [{a['severity']:8s}] {a['type']:18s} src={a['src']:16s} dst={a['dst']:16s} - {a['detail']}")

    print("\nResults saved to traffic_analysis.db — run `python3 app.py` to view the dashboard.")


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "sample_data/sample_capture.pcap"
    run_analysis(path)
