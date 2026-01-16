import argparse
import json
import os
import sqlite3
from datetime import datetime, timezone


def iso_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def read_version(base_dir: str) -> str:
    candidates = [
        os.path.join(base_dir, "VERSION"),
        os.path.join(base_dir, "..", "VERSION"),
    ]
    for path in candidates:
        try:
            with open(path, "r", encoding="utf-8") as f:
                value = f.read().strip()
                if value:
                    return value
        except OSError:
            continue
    return "unknown"


def vacuum_into_sql(backup_path: str) -> str:
    if not backup_path:
        raise ValueError("backup_path required")
    escaped_path = backup_path.replace("'", "''")
    return f"VACUUM INTO '{escaped_path}'"


def main() -> int:
    parser = argparse.ArgumentParser(description="SQLite backup using VACUUM INTO")
    parser.add_argument("--db", default=os.path.join("backend", "annafinder.db"))
    parser.add_argument("--outdir", default=os.path.join("evidence", "backups"))
    parser.add_argument("--label", default="")
    parser.add_argument("--note", default="")
    args = parser.parse_args()

    db_path = os.path.abspath(args.db)
    outdir = os.path.abspath(args.outdir)

    if not os.path.exists(db_path):
        raise SystemExit(f"DB not found: {db_path}")

    os.makedirs(outdir, exist_ok=True)

    label = args.label.strip() if args.label else datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"annafinder_backup_{label}.db"
    backup_path = os.path.join(outdir, backup_name)

    con = sqlite3.connect(db_path)
    try:
        con.execute("PRAGMA busy_timeout = 10000")
        # VACUUM INTO creates a consistent, compact snapshot copy.
        con.execute(vacuum_into_sql(backup_path))
    finally:
        con.close()

    metadata = {
        "created_at": iso_utc(),
        "db_path": db_path,
        "backup_file": backup_path,
        "app_version": read_version(os.path.dirname(db_path)),
        "env": os.getenv("ANNAFINDER_ENV", "dev"),
        "note": args.note,
    }

    meta_path = backup_path + ".json"
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)

    print(backup_path)
    print(meta_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
