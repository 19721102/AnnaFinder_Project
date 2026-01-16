import os
import sqlite3
import subprocess
import sys
from datetime import datetime, timedelta, timezone


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
BACKEND = os.path.join(ROOT, "backend")


def iso_utc(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def ensure_outbox(con):
    cur = con.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS email_outbox (
            id TEXT PRIMARY KEY,
            created_at TEXT NOT NULL,
            to_email TEXT NOT NULL,
            template TEXT NOT NULL,
            subject TEXT NOT NULL,
            body_text TEXT NOT NULL,
            body_html TEXT,
            status TEXT NOT NULL,
            attempts INTEGER NOT NULL DEFAULT 0,
            last_error TEXT NOT NULL DEFAULT '',
            correlation_id TEXT NOT NULL DEFAULT '',
            household_id TEXT NOT NULL DEFAULT '',
            user_id TEXT NOT NULL DEFAULT ''
        )
        """
    )
    con.commit()


def main():
    os.environ["ANNAFINDER_ENV"] = "test"
    db_path = os.path.join(BACKEND, "annafinder_test.db")
    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        ensure_outbox(con)
        cur = con.cursor()
        cur.execute("DELETE FROM email_outbox")
        old = iso_utc(datetime.now(timezone.utc) - timedelta(days=40))
        rows = [
            ("t1", old, "one@example.com", "reset_request", "s", "b", None, "sent"),
            ("t2", old, "two@example.com", "invite", "s", "b", None, "failed"),
        ]
        for r in rows:
            cur.execute(
                """
                INSERT INTO email_outbox (
                    id, created_at, to_email, template, subject, body_text, body_html, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                r,
            )
        con.commit()
    finally:
        con.close()

    purge = os.path.join(BACKEND, "outbox_purge.py")
    dry = subprocess.run(
        [
            sys.executable,
            purge,
            "--sent-days",
            "30",
            "--failed-days",
            "30",
            "--pending-days",
            "7",
            "--dry-run",
        ],
        cwd=ROOT,
        check=True,
    )
    if dry.returncode != 0:
        raise SystemExit("Dry-run failed")

    real = subprocess.run(
        [
            sys.executable,
            purge,
            "--sent-days",
            "30",
            "--failed-days",
            "30",
            "--pending-days",
            "7",
            "--mode",
            "delete",
            "--no-dry-run",
        ],
        cwd=ROOT,
        check=True,
    )
    if real.returncode != 0:
        raise SystemExit("Purge failed")

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    try:
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) AS c FROM email_outbox")
        remaining = cur.fetchone()["c"]
    finally:
        con.close()

    if remaining != 0:
        raise SystemExit(f"Expected 0 rows after purge, got {remaining}")
    print("PASS: outbox purge removed old rows.")


if __name__ == "__main__":
    main()
