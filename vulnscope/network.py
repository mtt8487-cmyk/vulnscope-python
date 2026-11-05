"""Bounded TCP connect scan; never use raw or stealth packets."""
import errno
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import MAX_WORKERS


def connect_port(host: str, port: int, timeout: float) -> dict:
    started = time.monotonic()
    state, detail = "error", ""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            state = "open"
            detail = "TCP connect succeeded"
    except ConnectionRefusedError:
        state, detail = "refused", "Target actively refused TCP connection"
    except (socket.timeout, TimeoutError):
        state, detail = "timeout", "TCP connect timed out"
    except OSError as exc:
        if exc.errno in (errno.ECONNREFUSED, 10061):
            state, detail = "refused", "TCP connection refused"
        elif exc.errno in (errno.ETIMEDOUT, 10060):
            state, detail = "timeout", "TCP connection timed out"
        else:
            state, detail = "error", f"Network error ({type(exc).__name__}; code {exc.errno})"
    return {
        "port": port, "state": state, "detail": detail,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
    }


def scan_ports(host: str, ports: list[int], timeout: float, workers: int = 8) -> list[dict]:
    with ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, workers))) as pool:
        futures = {pool.submit(connect_port, host, p, timeout): p for p in ports}
        results = []
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda row: row["port"])
