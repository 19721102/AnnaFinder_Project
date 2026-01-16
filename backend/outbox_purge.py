import argparse
import hashlib
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone
from typing import Tuple


BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def get_db_path() -> str:
    env = os.getenv("ANNAFINDER_ENV", "dev").strip().lower()
    if env == "test":
        return os.path.join(BASE_DIR, "annafinder_test.db")
    return os.path.join(BASE_DIR, "annafinder.db")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Purge old email_outbox records.")
    parser.add_argument("--db", default=get_db_path(), help="Path to SQLite DB")
    parser.add_argument(
        "--sent-days", type=int, default=int(os.getenv("OUTBOX_RETENTION_DAYS_SENT", "30"))
    )
    parser.add_argument(
        "--failed-days", type=int, default=int(os.getenv("OUTBOX_RETENTION_DAYS_FAILED", "30"))
    )
    parser.add_argument(
        "--pending-days", type=int, default=int(os.getenv("OUTBOX_RETENTION_DAYS_PENDING", "7"))
    )
    parser.add_argument(
        "--mode",
        default=os.getenv("OUTBOX_PURGE_MODE", "delete"),
        choices=["delete", "minimize_then_delete"],
    )
    parser.add_argument(
        "--dry-run",
        default=os.getenv("OUTBOX_PURGE_DRYRUN", "true").strip().lower() == "true",
        action=argparse.BooleanOptionalAction,
        help="Dry run (no changes).",
    )
    parser.add_argument(
        "--report-dir", default=os.path.join(os.path.dirname(BASE_DIR), "evidence", "maintenance")
    )
    parser.add_argument(
        "--minimize-extra-days",
        type=int,
        default=int(os.getenv("OUTBOX_MINIMIZE_EXTRA_DAYS", "7")),
    )
    return parser.parse_args()


def count_by_status(con: sqlite3.Connection, cutoff: str, status: str) -> int:
    cur = con.cursor()
    cur.execute(
        "SELECT COUNT(*) AS c FROM email_outbox WHERE status = ? AND created_at < ?",
        (status, cutoff),
    )
    return int(cur.fetchone()["c"])


def delete_by_status(con: sqlite3.Connection, cutoff: str, status: str) -> int:
    cur = con.cursor()
    cur.execute(
        "DELETE FROM email_outbox WHERE status = ? AND created_at < ?",
        (status, cutoff),
    )
    return cur.rowcount


def minimize_by_status(con: sqlite3.Connection, cutoff: str, status: str) -> int:
    cur = con.cursor()
    cur.execute(
        """
        UPDATE email_outbox
        SET to_email = '', subject = '', body_text = '', body_html = NULL, last_error = ''
        WHERE status = ? AND created_at < ?
        """,
        (status, cutoff),
    )
    return cur.rowcount


def hash_email(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def minimize_sensitive_fields(con: sqlite3.Connection, cutoff: str, status: str) -> int:
    cur = con.cursor()
    cur.execute(
        "SELECT id, to_email FROM email_outbox WHERE status = ? AND created_at < ?",
        (status, cutoff),
    )
    rows = cur.fetchall()
    if not rows:
        return 0
    for row in rows:
        cur.execute(
            """
            UPDATE email_outbox
            SET to_email = ?, subject = '', body_text = '', body_html = NULL, last_error = ''
            WHERE id = ?
            """,
            (hash_email(row["to_email"]), row["id"]),
        )
    return len(rows)


def ensure_report_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def write_report(path: str, lines: Tuple[str, ...]) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines))


def main() -> int:
    args = parse_args()
    start = time.time()
    report_dir = args.report_dir
    ensure_report_dir(report_dir)

    con = sqlite3.connect(args.db)
    con.row_factory = sqlite3.Row
    try:
        now = utc_now()
        cutoffs = {
            "sent": iso_utc(now - timedelta(days=max(args.sent_days, 0))),
            "failed": iso_utc(now - timedelta(days=max(args.failed_days, 0))),
            "pending": iso_utc(now - timedelta(days=max(args.pending_days, 0))),
        }

        counts = {
            "sent": count_by_status(con, cutoffs["sent"], "sent"),
            "failed": count_by_status(con, cutoffs["failed"], "failed"),
            "pending": count_by_status(con, cutoffs["pending"], "pending"),
        }

        minimized = {"sent": 0, "failed": 0, "pending": 0}
        deleted = {"sent": 0, "failed": 0, "pending": 0}

        if not args.dry_run:
            if args.mode == "minimize_then_delete":
                minimized["sent"] = minimize_sensitive_fields(con, cutoffs["sent"], "sent")
                minimized["failed"] = minimize_sensitive_fields(con, cutoffs["failed"], "failed")
                minimized["pending"] = minimize_sensitive_fields(con, cutoffs["pending"], "pending")
                con.commit()

                extra_cutoffs = {
                    "sent": iso_utc(
                        now - timedelta(days=max(args.sent_days + args.minimize_extra_days, 0))
                    ),
                    "failed": iso_utc(
                        now - timedelta(days=max(args.failed_days + args.minimize_extra_days, 0))
                    ),
                    "pending": iso_utc(
                        now - timedelta(days=max(args.pending_days + args.minimize_extra_days, 0))
                    ),
                }
                deleted["sent"] = delete_by_status(con, extra_cutoffs["sent"], "sent")
                deleted["failed"] = delete_by_status(con, extra_cutoffs["failed"], "failed")
                deleted["pending"] = delete_by_status(con, extra_cutoffs["pending"], "pending")
            else:
                deleted["sent"] = delete_by_status(con, cutoffs["sent"], "sent")
                deleted["failed"] = delete_by_status(con, cutoffs["failed"], "failed")
                deleted["pending"] = delete_by_status(con, cutoffs["pending"], "pending")
            con.commit()

        duration_ms = int((time.time() - start) * 1000)
        report_name = f"outbox_purge_{now.strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(report_dir, report_name)
        lines = (
            "# Outbox Purge Report",
            "",
            f"Generated: {iso_utc(now)}",
            f"DB: {args.db}",
            f"Mode: {args.mode}",
            f"Dry-run: {args.dry_run}",
            f"Retention days (sent/failed/pending): {args.sent_days}/{args.failed_days}/{args.pending_days}",
            f"Cutoffs: sent<{cutoffs['sent']}, failed<{cutoffs['failed']}, pending<{cutoffs['pending']}",
            "",
            "## Candidates",
            f"- sent: {counts['sent']}",
            f"- failed: {counts['failed']}",
            f"- pending: {counts['pending']}",
            "",
            "## Actions",
            f"- minimized (sent/failed/pending): {minimized['sent']}/{minimized['failed']}/{minimized['pending']}",
            f"- deleted (sent/failed/pending): {deleted['sent']}/{deleted['failed']}/{deleted['pending']}",
            "",
            f"Duration: {duration_ms} ms",
        )
        write_report(report_path, lines)
        print(f"Report: {report_path}")
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    raise SystemExit(main())
