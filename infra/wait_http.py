import sys
import time
from typing import Iterable
from urllib.error import URLError, HTTPError
from urllib.request import urlopen


DEFAULT_TIMEOUT_SECONDS = 120
DEFAULT_INTERVAL_SECONDS = 2


def _is_status_ok(status: int) -> bool:
    if 200 <= status < 400:
        return True
    return status in (401, 403)


def _check_url(url: str, timeout: float) -> bool:
    try:
        with urlopen(url, timeout=timeout) as response:
            return _is_status_ok(getattr(response, "status", response.getcode()))
    except HTTPError as exc:
        return _is_status_ok(exc.code)
    except (URLError, TimeoutError):
        return False


def _parse_args(argv: list[str]) -> tuple[list[str], int, int]:
    timeout = DEFAULT_TIMEOUT_SECONDS
    interval = DEFAULT_INTERVAL_SECONDS
    urls: list[str] = []
    for arg in argv:
        if arg.startswith("--timeout="):
            timeout = int(arg.split("=", 1)[1])
        elif arg.startswith("--interval="):
            interval = int(arg.split("=", 1)[1])
        else:
            urls.append(arg)
    return urls, timeout, interval


def _wait_for_urls(urls: Iterable[str], timeout: int, interval: int) -> bool:
    urls = list(urls)
    if not urls:
        print("No URLs provided.")
        return False
    deadline = time.monotonic() + timeout
    pending = set(urls)
    while time.monotonic() < deadline:
        ready = [url for url in pending if _check_url(url, timeout=2)]
        for url in ready:
            pending.discard(url)
        if not pending:
            return True
        time.sleep(interval)
    print(f"Timed out waiting for: {', '.join(sorted(pending))}")
    return False


def main(argv: list[str]) -> int:
    urls, timeout, interval = _parse_args(argv)
    ok = _wait_for_urls(urls, timeout, interval)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
