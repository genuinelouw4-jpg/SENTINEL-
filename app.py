"""
Threat Intelligence Dashboard
A security analyst portfolio project built with Flask, SQLite, and Python.
"""

from flask import Flask, render_template, jsonify
import sqlite3
import os
from datetime import datetime

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "data", "threats.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def summary():
    conn = get_db()
    cur = conn.cursor()

    total = cur.execute("SELECT COUNT(*) FROM threats").fetchone()[0]
    critical = cur.execute("SELECT COUNT(*) FROM threats WHERE severity='Critical'").fetchone()[0]
    high = cur.execute("SELECT COUNT(*) FROM threats WHERE severity='High'").fetchone()[0]
    blocked = cur.execute("SELECT COUNT(*) FROM threats WHERE status='Blocked'").fetchone()[0]

    conn.close()
    return jsonify({
        "total_threats": total,
        "critical": critical,
        "high": high,
        "blocked": blocked
    })


@app.route("/api/threats")
def threats():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT id, ip_address, threat_type, severity, country, status, first_seen, last_seen
        FROM threats
        ORDER BY last_seen DESC
        LIMIT 50
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/threats/by_type")
def by_type():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT threat_type, COUNT(*) as count
        FROM threats
        GROUP BY threat_type
        ORDER BY count DESC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/threats/by_country")
def by_country():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT country, COUNT(*) as count
        FROM threats
        GROUP BY country
        ORDER BY count DESC
        LIMIT 10
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/threats/timeline")
def timeline():
    conn = get_db()
    cur = conn.cursor()
    rows = cur.execute("""
        SELECT DATE(first_seen) as date, COUNT(*) as count
        FROM threats
        GROUP BY DATE(first_seen)
        ORDER BY date ASC
    """).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(debug=True, port=5000)
