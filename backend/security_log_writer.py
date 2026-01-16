import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

MAX_BYTES = 10 * 1024 * 1024
MAX_FILES = 5
MAX_LINE_LENGTH = 8192

SECURITY_LOG_DIR = os.getenv("SECURITY_LOG_DIR", "").strip()

SECURITY_LOGGER = logging.getLogger("annafinder.security")
SECURITY_LOGGER.propagate = False
SECURITY_LOGGER.setLevel(logging.INFO)
SECURITY_HANDLER: Optional[logging.Handler] = None

if SECURITY_LOG_DIR:
    try:
        log_dir_path = Path(SECURITY_LOG_DIR)
        log_dir_path.mkdir(parents=True, exist_ok=True)
        log_file = log_dir_path / "security_events.jsonl"
        SECURITY_HANDLER = RotatingFileHandler(
            log_file,
            maxBytes=MAX_BYTES,
            backupCount=MAX_FILES,
            encoding="utf-8",
        )
        SECURITY_HANDLER.setFormatter(logging.Formatter("%(message)s"))
        SECURITY_LOGGER.addHandler(SECURITY_HANDLER)
    except OSError:
        SECURITY_HANDLER = None

if not SECURITY_HANDLER:
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(logging.Formatter("%(message)s"))
    SECURITY_LOGGER.addHandler(stream_handler)
    SECURITY_HANDLER = stream_handler


def write_security_log(line: str) -> None:
    if not SECURITY_HANDLER:
        return
    payload = line if len(line) <= MAX_LINE_LENGTH else line[:MAX_LINE_LENGTH]
    try:
        SECURITY_LOGGER.info(payload)
    except Exception:
        pass
