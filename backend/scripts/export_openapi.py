import argparse
import json
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = BACKEND_DIR.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.append(str(BACKEND_DIR))

from backend.main import app  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Export the FastAPI OpenAPI schema to a JSON file."
    )
    parser.add_argument(
        "--out",
        "-o",
        default="docs/openapi.json",
        help="Target file path where the OpenAPI JSON should be written.",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    try:
        schema = app.openapi()
    except Exception as exc:
        raise SystemExit(f"Failed to build OpenAPI schema: {exc}") from exc
    target = Path(args.out)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(schema, indent=2), encoding="utf-8")


if __name__ == "__main__":  # pragma: no cover
    main()
