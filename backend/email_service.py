import os
import smtplib
import sqlite3
import ssl
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from typing import Dict, Optional

from security_events import sanitize_str


TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "email")


class _SafeDict(dict):
    def __missing__(self, key: str) -> str:
        return ""


def _sanitize_error(message: str) -> str:
    return sanitize_str(message, 240)


def _load_template(name: str, lang: str) -> str:
    path = os.path.join(TEMPLATES_DIR, f"{name}_{lang}.txt")
    if not os.path.exists(path):
        path = os.path.join(TEMPLATES_DIR, f"{name}_en.txt")
    with open(path, "r", encoding="utf-8") as handle:
        return handle.read()


def render_email_body(name: str, lang: str, context: Dict[str, str]) -> str:
    template = _load_template(name, lang)
    return template.format_map(_SafeDict(context))


def enqueue_email(
    db_path: str,
    to_email: str,
    template: str,
    subject: str,
    body_text: str,
    body_html: Optional[str],
    status: str,
    correlation_id: str,
    household_id: Optional[str],
    user_id: Optional[str],
) -> None:
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO email_outbox (
                id, created_at, to_email, template, subject, body_text, body_html,
                status, attempts, last_error, correlation_id, household_id, user_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                os.urandom(16).hex(),
                _utc_now_iso(),
                to_email,
                template,
                subject,
                body_text,
                body_html,
                status,
                0,
                "",
                correlation_id,
                household_id or "",
                user_id or "",
            ),
        )
        conn.commit()
    finally:
        conn.close()


def send_pending_emails(
    db_path: str,
    batch_size: int = 20,
    emit_event_fn=None,
) -> Dict[str, int]:
    smtp_host = os.getenv("SMTP_HOST", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_pass = os.getenv("SMTP_PASS", "").strip()
    smtp_tls = os.getenv("SMTP_TLS", "true").strip().lower() == "true"
    smtp_from = os.getenv("SMTP_FROM", "").strip()
    smtp_reply_to = os.getenv("SMTP_REPLY_TO", "").strip()

    if not smtp_host:
        return {"sent": 0, "failed": 0, "skipped": batch_size}

    if not smtp_tls:
        if emit_event_fn:
            emit_event_fn(
                {
                    "event": "EMAIL_TLS_FAIL",
                    "severity": "HIGH",
                    "outcome": "FAIL",
                    "target": {"resource": "smtp"},
                    "meta": {"reason": "tls_disabled"},
                },
                correlation_id="",
                household_id=None,
                user_id=None,
            )
        raise RuntimeError("SMTP_TLS must be true when SMTP is configured.")

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    sent = 0
    failed = 0
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, to_email, subject, body_text, body_html, template, correlation_id, household_id, user_id
            FROM email_outbox
            WHERE status = 'pending'
            ORDER BY created_at ASC
            LIMIT ?
            """,
            (batch_size,),
        )
        rows = cur.fetchall()
        if not rows:
            return {"sent": 0, "failed": 0, "skipped": 0}

        context = ssl.create_default_context()
        with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
            server.starttls(context=context)
            if smtp_user and smtp_pass:
                server.login(smtp_user, smtp_pass)

            for row in rows:
                try:
                    msg = EmailMessage()
                    msg["From"] = smtp_from or smtp_user or "no-reply@example.com"
                    msg["To"] = row["to_email"]
                    msg["Subject"] = row["subject"]
                    msg["Date"] = formatdate(localtime=False)
                    msg["Message-ID"] = make_msgid(domain=None)
                    if smtp_reply_to:
                        msg["Reply-To"] = smtp_reply_to
                    msg["X-AnnaFinder-Message-Type"] = row["template"]
                    msg.set_content(row["body_text"])
                    if row["body_html"]:
                        msg.add_alternative(row["body_html"], subtype="html")
                    server.send_message(msg)
                    cur.execute(
                        "UPDATE email_outbox SET status = 'sent' WHERE id = ?",
                        (row["id"],),
                    )
                    sent += 1
                    if emit_event_fn:
                        emit_event_fn(
                            {
                                "event": "EMAIL_SENT",
                                "severity": "LOW",
                                "outcome": "SUCCESS",
                                "target": {"resource": "email", "id": row["id"]},
                                "meta": {"template": sanitize_str(row["template"], 64)},
                            },
                            correlation_id=row["correlation_id"],
                            household_id=row["household_id"] or None,
                            user_id=row["user_id"] or None,
                        )
                except Exception as exc:  # noqa: BLE001
                    failed += 1
                    error = _sanitize_error(str(exc))
                    cur.execute(
                        """
                        UPDATE email_outbox
                        SET status = 'failed', attempts = attempts + 1, last_error = ?
                        WHERE id = ?
                        """,
                        (error, row["id"]),
                    )
                    if emit_event_fn:
                        emit_event_fn(
                            {
                                "event": "EMAIL_FAILED",
                                "severity": "MED",
                                "outcome": "FAIL",
                                "target": {"resource": "email", "id": row["id"]},
                                "meta": {"error": error},
                            },
                            correlation_id=row["correlation_id"],
                            household_id=row["household_id"] or None,
                            user_id=row["user_id"] or None,
                        )
                        emit_event_fn(
                            {
                                "event": "EMAIL_SEND_FAIL",
                                "severity": "MED",
                                "outcome": "FAIL",
                                "target": {"resource": "email", "id": row["id"]},
                                "meta": {"template": sanitize_str(row["template"], 64)},
                            },
                            correlation_id=row["correlation_id"],
                            household_id=row["household_id"] or None,
                            user_id=row["user_id"] or None,
                        )
        conn.commit()
    finally:
        conn.close()
    return {"sent": sent, "failed": failed, "skipped": 0}


def _utc_now_iso() -> str:
    return _iso_utc_now()


def _iso_utc_now() -> str:
    return datetime_utc().replace("+00:00", "Z")


def datetime_utc() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()
