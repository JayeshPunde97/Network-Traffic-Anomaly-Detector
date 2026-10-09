"""
app.py

Flask web dashboard for the Network Traffic Anomaly Detector.
Reads from the SQLite database populated by analyze_traffic.py and
displays a summary, the flagged anomalies, and the raw traffic flows.

Run:
    python3 analyze_traffic.py sample_data/sample_capture.pcap   # populate DB first
    python3 app.py                                                # then start the dashboard
Then open http://127.0.0.1:5000 in your browser.
"""

from datetime import datetime

from flask import Flask, render_template

import db

app = Flask(__name__)


def fmt_time(ts):
    return datetime.fromtimestamp(ts).strftime("%H:%M:%S")


@app.route("/")
def dashboard():
    conn = db.get_connection()
    stats = db.get_summary_stats(conn)
    recent_anomalies = db.get_all_anomalies(conn)[-5:][::-1]
    conn.close()
    return render_template(
        "index.html", stats=stats, recent_anomalies=recent_anomalies, fmt_time=fmt_time
    )


@app.route("/anomalies")
def anomalies():
    conn = db.get_connection()
    rows = db.get_all_anomalies(conn)
    conn.close()
    return render_template("anomalies.html", anomalies=rows, fmt_time=fmt_time)


@app.route("/traffic")
def traffic():
    conn = db.get_connection()
    rows = db.get_all_flows(conn)
    conn.close()
    return render_template("traffic.html", flows=rows, fmt_time=fmt_time)


if __name__ == "__main__":
    app.run(debug=True)
