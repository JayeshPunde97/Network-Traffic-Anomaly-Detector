"""
db.py

Thin SQLite layer for the Network Traffic Anomaly Detector.
Two tables:
    flows      - aggregated traffic summary (who talked to whom, how much)
    anomalies  - flagged suspicious events with a reason and severity
"""

import sqlite3

DB_PATH = "traffic_analysis.db"


def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("DROP TABLE IF EXISTS flows")
    cur.execute("DROP TABLE IF EXISTS anomalies")

    cur.execute(
        """
        CREATE TABLE flows (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_ip TEXT NOT NULL,
            dst_ip TEXT NOT NULL,
            protocol TEXT NOT NULL,
            packet_count INTEGER NOT NULL,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL
        )
        """
    )

    cur.execute(
        """
        CREATE TABLE anomalies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            detected_at REAL NOT NULL,
            src_ip TEXT NOT NULL,
            dst_ip TEXT,
            anomaly_type TEXT NOT NULL,
            detail TEXT NOT NULL,
            severity TEXT NOT NULL
        )
        """
    )

    conn.commit()
    conn.close()


def insert_flow(conn, src_ip, dst_ip, protocol, packet_count, first_seen, last_seen):
    conn.execute(
        """
        INSERT INTO flows (src_ip, dst_ip, protocol, packet_count, first_seen, last_seen)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (src_ip, dst_ip, protocol, packet_count, first_seen, last_seen),
    )


def insert_anomaly(conn, detected_at, src_ip, dst_ip, anomaly_type, detail, severity):
    conn.execute(
        """
        INSERT INTO anomalies (detected_at, src_ip, dst_ip, anomaly_type, detail, severity)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (detected_at, src_ip, dst_ip, anomaly_type, detail, severity),
    )


def get_all_flows(conn, limit=200):
    return conn.execute(
        "SELECT * FROM flows ORDER BY packet_count DESC LIMIT ?", (limit,)
    ).fetchall()


def get_all_anomalies(conn):
    return conn.execute(
        "SELECT * FROM anomalies ORDER BY detected_at ASC"
    ).fetchall()


def get_summary_stats(conn):
    total_flows = conn.execute("SELECT COUNT(*) FROM flows").fetchone()[0]
    total_packets = conn.execute("SELECT SUM(packet_count) FROM flows").fetchone()[0] or 0
    total_anomalies = conn.execute("SELECT COUNT(*) FROM anomalies").fetchone()[0]
    by_type = conn.execute(
        "SELECT anomaly_type, COUNT(*) as cnt FROM anomalies GROUP BY anomaly_type"
    ).fetchall()
    return {
        "total_flows": total_flows,
        "total_packets": total_packets,
        "total_anomalies": total_anomalies,
        "by_type": by_type,
    }
