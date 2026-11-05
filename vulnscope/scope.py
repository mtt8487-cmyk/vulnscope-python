"""Strict IP-only allowlist: never resolve an untrusted hostname."""
import ipaddress
import os
from .config import MAX_PORTS

_PRIVATE_LABS = tuple(ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "fc00::/7", "::1/128",
))


def parse_ip(target: str) -> str:
    """Normalize localhost or an IP literal; reject URL, domain, and DNS."""
    raw = target.strip()
    if raw.lower() == "localhost":
        return "127.0.0.1"
    try:
        ip = ipaddress.ip_address(raw)
    except ValueError as exc:
        raise ValueError("Use localhost or a numeric IP address (not a URL or hostname).") from exc
    if not any(ip in network for network in _PRIVATE_LABS):
        raise ValueError("Only loopback and private lab IP addresses are supported.")
    if ip.is_multicast or ip.is_unspecified:
        raise ValueError("Multicast and unspecified targets are forbidden.")
    return str(ip)


def allowed_targets() -> set[str]:
    """Extra exact IP literals may be configured by the computer owner only."""
    allowed = {"127.0.0.1", "::1"}
    for raw in os.getenv("VULNSCOPE_ALLOWED_TARGETS", "").split(","):
        if raw.strip():
            allowed.add(parse_ip(raw))
    return allowed


def authorize(target: str, acknowledged: bool, allowlist: set[str] | None = None) -> str:
    if not acknowledged:
        raise PermissionError("You must confirm ownership or explicit assessment authorization.")
    normalized = parse_ip(target)
    if normalized not in (allowed_targets() if allowlist is None else allowlist):
        raise PermissionError("Target is not on the exact-IP allowlist. Localhost is enabled by default.")
    return normalized


def parse_ports(raw: str) -> list[int]:
    """Comma-separated ports and ranges; reject excessive or malformed inputs."""
    if not raw.strip():
        raise ValueError("Choose at least one port.")
    ports: set[int] = set()
    for token in raw.split(","):
        item = token.strip()
        if not item:
            raise ValueError("Empty port entry.")
        if "-" in item:
            parts = item.split("-")
            if len(parts) != 2 or not all(p.isdecimal() for p in parts):
                raise ValueError(f"Invalid port range: {item}")
            start, end = (int(x) for x in parts)
            if start > end or end - start + 1 > MAX_PORTS:
                raise ValueError("Port range invalid or too wide (maximum 32 ports).")
            ports.update(range(start, end + 1))
        elif item.isdecimal():
            ports.add(int(item))
        else:
            raise ValueError(f"Invalid port: {item}")
        if len(ports) > MAX_PORTS:
            raise ValueError(f"Choose no more than {MAX_PORTS} distinct ports.")
    if not all(1 <= p <= 65535 for p in ports):
        raise ValueError("Ports must be from 1 to 65535.")
    return sorted(ports)
