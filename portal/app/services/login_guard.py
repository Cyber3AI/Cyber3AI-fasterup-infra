"""Login rate-limiter / lockout, backed by portal.db (shared across gunicorn workers).

Fail-open on DB errors (never lock out everyone if the DB hiccups).
Two thresholds inside a sliding window:
  - per (ip, username): MAX_PER_USER_IP failures -> lock
  - per ip (any username): MAX_PER_IP failures  -> lock (stops username-spraying from one IP)
Each new failure while locked pushes the unlock time forward (last-failure based).
"""
import os
import sqlite3
import time

DB_PATH = os.getenv('PORTAL_DB_PATH', '/opt/fasterup-portal/data/portal.db')

WINDOW = 900            # sliding window (seconds) counted for lockout
MAX_PER_USER_IP = 5     # failures per (ip, username) before lock
MAX_PER_IP = 20         # failures per ip (any username) before lock
LOCK_SECONDS = 900      # lockout duration from the last failure


def _conn():
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def _ensure(conn):
    conn.execute("""CREATE TABLE IF NOT EXISTS login_attempts (
        ip TEXT NOT NULL, username TEXT NOT NULL, ts REAL NOT NULL)""")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_la_ts ON login_attempts(ts)")


def retry_after(ip, username):
    """Seconds the caller must wait if currently locked, else 0."""
    now = time.time()
    cutoff = now - WINDOW
    try:
        conn = _conn()
        _ensure(conn)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*), MAX(ts) FROM login_attempts "
                    "WHERE ip=? AND username=? AND ts>?", (ip, username, cutoff))
        n_ui, last_ui = cur.fetchone()
        cur.execute("SELECT COUNT(*), MAX(ts) FROM login_attempts "
                    "WHERE ip=? AND ts>?", (ip, cutoff))
        n_ip, last_ip = cur.fetchone()
        conn.close()
    except Exception:
        return 0
    locked = 0
    if n_ui and n_ui >= MAX_PER_USER_IP and last_ui:
        locked = max(locked, int(last_ui + LOCK_SECONDS - now))
    if n_ip and n_ip >= MAX_PER_IP and last_ip:
        locked = max(locked, int(last_ip + LOCK_SECONDS - now))
    return max(0, locked)


def record_failure(ip, username):
    try:
        conn = _conn()
        _ensure(conn)
        conn.execute("INSERT INTO login_attempts (ip, username, ts) VALUES (?,?,?)",
                     (ip, username, time.time()))
        conn.execute("DELETE FROM login_attempts WHERE ts < ?", (time.time() - WINDOW * 4,))
        conn.commit()
        conn.close()
    except Exception:
        pass


def clear(ip, username):
    """Clear counters for a successful login."""
    try:
        conn = _conn()
        _ensure(conn)
        conn.execute("DELETE FROM login_attempts WHERE ip=? AND username=?", (ip, username))
        conn.commit()
        conn.close()
    except Exception:
        pass
