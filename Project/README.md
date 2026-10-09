# Network Traffic Anomaly Detector

A lightweight tool that captures/parses network traffic, applies
threshold-based rules to flag suspicious behavior, stores the results in
SQLite, and displays them on a simple Flask dashboard.

Built as a final-year project to explore how SOC teams detect anomalies
in network traffic using packet-level analysis (Wireshark/TShark-style
tooling) combined with a rule-based detection engine.

## What it detects

| Anomaly Type | How it's detected |
|---|---|
| **Port Scan** | A single source sends SYN-only packets to 15+ distinct ports on one destination within a 5-second window, without ever completing the TCP handshake. |
| **SYN Flood** | A single source sends 100+ unanswered SYN packets to one destination within 5 seconds — classic protocol-level DoS. |
| **Volumetric Spike** | A single source sends 150+ packets to one destination within 5 seconds — well above normal baseline traffic. |
| **Distributed Volumetric (Amplification-style)** | 200+ packets from 8+ distinct source IPs converge on a single destination within 5 seconds — mirrors a reflection/amplification DDoS pattern, where no single source looks anomalous on its own. |

All thresholds are simple constants at the top of `analyze_traffic.py`,
tuned against the bundled sample traffic and easy to adjust for a real
environment's baseline.

## How it works

1. **Capture / Input** — `generate_sample_traffic.py` builds a realistic
   sample `.pcap` with normal background traffic plus four injected
   attack patterns (for demo purposes, since this avoids needing live
   network capture permissions). In a real deployment, any `.pcap`
   captured with Wireshark/TShark/tcpdump can be dropped in instead.
2. **Analysis** — `analyze_traffic.py` reads the pcap with Scapy,
   extracts per-packet flow records (source/destination IP, port,
   protocol, TCP flags), aggregates them, and runs them through four
   sliding-window detection rules.
3. **Storage** — results are persisted to `traffic_analysis.db` (SQLite):
   one table of aggregated traffic flows, one table of flagged anomalies.
4. **Dashboard** — `app.py` (Flask) serves three pages: a summary
   dashboard, a full anomalies list, and the raw traffic flow table.

## Running it

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Generate sample traffic (or supply your own .pcap)
python3 generate_sample_traffic.py

# 3. Run the analysis — this populates traffic_analysis.db
python3 analyze_traffic.py sample_data/sample_capture.pcap

# 4. Start the dashboard
python3 app.py
```

Then open `http://127.0.0.1:5000` in your browser.

To analyze your own capture instead of the sample data:

```bash
python3 analyze_traffic.py path/to/your_capture.pcap
python3 app.py
```

## Project structure

```
network-traffic-anomaly-detector/
├── generate_sample_traffic.py   # builds sample pcap with injected attacks
├── analyze_traffic.py           # core detection logic (the heart of the project)
├── db.py                        # SQLite schema + helper functions
├── app.py                       # Flask dashboard
├── templates/                   # HTML templates for the dashboard
├── static/style.css             # dashboard styling
├── sample_data/                 # generated sample .pcap lives here
└── requirements.txt
```

## Known limitations / possible improvements

- Detection is currently **rule/threshold-based**, not machine learning.
  A natural next step would be a learning-based baseline (e.g. moving
  average + standard deviation, or an isolation forest model) so
  thresholds adapt automatically instead of being hardcoded.
- No real-time alerting yet (e.g. email/Slack webhook on detection).
- Designed around offline `.pcap` analysis; live interface sniffing
  would need to run with elevated/admin privileges on the host machine.

## Tech stack

Python, Scapy (packet parsing), Flask (dashboard), SQLite (storage).
