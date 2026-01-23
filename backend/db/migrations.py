from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ALEMBIC_INI = Path(__file__).resolve().parents[1] / "alembic.ini"


def alembic_upgrade_head(database_url: str) -> None:
    """Run Alembic's CLI upgrade head pointing at the supplied URL."""
    env = os.environ.copy()
    env["DATABASE_URL"] = database_url
    subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        check=True,
        cwd=str(ALEMBIC_INI.parent),
        env=env,
    )
