"""Service hints are never treated as identification proof."""
import socket
from .config import SERVICE_HINTS, BANNER_PORTS


def inspect_service(host: str, port: int, timeout: float) -> dict:
    hint = SERVICE_HINTS.get(port, "Unknown")
    result = {"port": port, "hint": hint, "evidence": "", "confidence": "inferred" if hint != "Unknown" else "unknown"}
    if port not in BANNER_PORTS:
        return result
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(min(timeout, 0.35))
            banner = conn.recv(256).decode("ascii", errors="replace").strip()
            if banner:
                result["evidence"] = banner[:200]
                result["confidence"] = "observed banner (unverified identity)"
    except (OSError, ValueError):
        pass
    return result
