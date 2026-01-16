import argparse
import os
import sqlite3
from datetime import datetime


def is_sqlite_file(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            header = f.read(16)
        return header == b"SQLite format 3\x00"
    except OSError:
        return False


def existing_tables(con: sqlite3.Connection) -> set:
    cur = con.cursor()
    cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
    return {row[0] for row in cur.fetchall()}


def main() -> int:
    parser = argparse.ArgumentParser(description="SQLite restore with validation")
    parser.add_argument("--db", default=os.path.join("backend", "annafinder.db"))
    parser.add_argument("--backup", required=True)
    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    backup_path = os.path.abspath(args.backup)

    if not os.path.exists(backup_path):
        raise SystemExit(f"Backup not found: {backup_path}")
    if not is_sqlite_file(backup_path):
        raise SystemExit("Backup does not look like a SQLite database")

    if not os.path.exists(db_path):
        raise SystemExit(f"DB not found: {db_path}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    pre_bak = f"{db_path}.pre_restore_{ts}.bak"
    os.replace(db_path, pre_bak)

    try:
        os.replace(backup_path, db_path)
        con = sqlite3.connect(db_path)
        try:
            tables = existing_tables(con)
            for t in ["items", "events", "routines", "family_members"]:
                if t in tables:
                    con.execute(f"SELECT COUNT(*) FROM {t}")
            con.execute("SELECT 1")
        finally:
            con.close()
    except Exception as exc:
        if os.path.exists(db_path):
            os.replace(db_path, f"{db_path}.failed_{ts}.bak")
        os.replace(pre_bak, db_path)
        raise SystemExit(f"Restore failed; rolled back. Error: {exc}") from exc

    print(f"Restored from {backup_path}")
    print(f"Previous DB backup: {pre_bak}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
