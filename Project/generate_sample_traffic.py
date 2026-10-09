"""
generate_sample_traffic.py

Generates a sample .pcap file containing a mix of normal, everyday network
traffic plus a few injected attack patterns (port scan, SYN flood, DNS
amplification-style burst). This lets the anomaly detector be demoed
and tested without needing a live network capture.

Run:
    python3 generate_sample_traffic.py
Output:
    sample_data/sample_capture.pcap
"""

import random
import time

from scapy.all import IP, TCP, UDP, Ether, wrpcap

random.seed(42)

packets = []
base_time = time.time() - 300  # pretend capture started 5 minutes ago


def add_packet(pkt, t_offset):
    pkt.time = base_time + t_offset
    packets.append(pkt)


# ---------------------------------------------------------------------------
# 1. Normal background traffic: a handful of internal hosts talking to a
#    few common external-style services (HTTP, HTTPS, DNS) at a relaxed rate.
# ---------------------------------------------------------------------------
internal_hosts = ["10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.14", "10.0.0.15"]
common_services = [
    ("93.184.216.34", 443),   # HTTPS
    ("172.217.14.206", 443),  # HTTPS
    ("151.101.1.69", 80),     # HTTP
]
dns_server = "8.8.8.8"

t = 0.0
for _ in range(400):
    src = random.choice(internal_hosts)
    dst, dport = random.choice(common_services)
    sport = random.randint(1025, 65000)
    flags = random.choice(["S", "SA", "A", "PA", "FA"])
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    t += random.uniform(0.05, 0.6)
    add_packet(pkt, t)

# Occasional normal DNS lookups
for _ in range(60):
    src = random.choice(internal_hosts)
    pkt = Ether() / IP(src=src, dst=dns_server) / UDP(sport=random.randint(1025, 65000), dport=53)
    t += random.uniform(0.3, 2.0)
    add_packet(pkt, t)

# ---------------------------------------------------------------------------
# 2. Injected anomaly #1: Port scan.
#    A single external host rapidly probes many sequential ports on one
#    internal target using SYN-only packets (no completed handshake).
# ---------------------------------------------------------------------------
scanner_ip = "203.0.113.66"
scan_target = "10.0.0.5"
scan_start_t = t + 5
for i, port in enumerate(range(20, 1044)):  # 1024 ports scanned
    pkt = Ether() / IP(src=scanner_ip, dst=scan_target) / TCP(
        sport=random.randint(40000, 60000), dport=port, flags="S"
    )
    add_packet(pkt, scan_start_t + i * 0.01)  # very fast, ~10ms apart

t = scan_start_t + 1024 * 0.01 + 5

# ---------------------------------------------------------------------------
# 3. Injected anomaly #2: SYN flood.
#    One source IP sends a very high volume of SYN packets to a single
#    destination/port, never completing the handshake.
# ---------------------------------------------------------------------------
flood_src = "198.51.100.23"
flood_target = "10.0.0.8"
flood_start_t = t
for i in range(2000):
    pkt = Ether() / IP(src=flood_src, dst=flood_target) / TCP(
        sport=random.randint(1025, 65000), dport=80, flags="S"
    )
    add_packet(pkt, flood_start_t + i * 0.002)  # 2ms apart -> very high rate

t = flood_start_t + 2000 * 0.002 + 5

# ---------------------------------------------------------------------------
# 4. Injected anomaly #3: DNS amplification-style burst.
#    Several "reflector" servers all send large UDP responses from port 53
#    to a single victim within a short window.
# ---------------------------------------------------------------------------
victim_ip = "10.0.0.20"
reflectors = [f"198.51.100.{n}" for n in range(30, 46)]
amp_start_t = t
for i in range(600):
    src = random.choice(reflectors)
    pkt = Ether() / IP(src=src, dst=victim_ip) / UDP(sport=53, dport=random.randint(1025, 65000))
    add_packet(pkt, amp_start_t + i * 0.01)

# ---------------------------------------------------------------------------
# Write everything out, sorted by time (as a real capture would be)
# ---------------------------------------------------------------------------
packets.sort(key=lambda p: p.time)
wrpcap("sample_data/sample_capture.pcap", packets)

print(f"Wrote {len(packets)} packets to sample_data/sample_capture.pcap")
print("Includes: normal traffic, a port scan, a SYN flood, and a DNS amplification-style burst.")
