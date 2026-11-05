"""End-to-end assessment orchestrator. Explicit target consent is mandatory."""
import time
from datetime import datetime, timezone
from .scope import authorize, parse_ports
from .config import HTTP_PORTS, HTTPS_PORTS, MAX_TIMEOUT, MAX_SCAN_SECONDS
from .network import scan_ports
from .services import inspect_service
from .http_checks import get_headers
from .tls_checks import inspect_tls
from .findings import analyze, SEVERITIES


def run_scan(target: str, ports: str, acknowledged: bool, timeout: float = 0.75,
             workers: int = 6, allowlist: set[str] | None = None) -> dict:
    """Run a bounded, read-only assessment against a preapproved IP literal."""
    host = authorize(target, acknowledged, allowlist)
    chosen = parse_ports(ports)
    if not (0.2 <= timeout <= MAX_TIMEOUT):
        raise ValueError("Connection timeout must be between 0.2 and 2.0 seconds.")
    if not (1 <= workers <= 8):
        raise ValueError("Worker count must be between 1 and 8.")
    # Guard against a deliberately slow low-worker configuration. A tight
    # overall wall-clock guarantee is not possible with blocking OS connects.
    if len(chosen) * timeout / workers > 18:
        raise ValueError("Estimated TCP phase exceeds budget. Reduce ports/timeout or increase workers.")
    started = time.monotonic()
    clock = datetime.now(timezone.utc).isoformat()
    port_results = scan_ports(host, chosen, timeout, workers)
    services, http, tls = [], [], []
    scan_incomplete = False
    for port_data in port_results:
        if port_data["state"] != "open":
            continue
        port = port_data["port"]
        if time.monotonic() - started >= MAX_SCAN_SECONDS:
            scan_incomplete = True
            break
        services.append(inspect_service(host, port, timeout))
        if port in HTTPS_PORTS:
            tls.append(inspect_tls(host, port, timeout))
            http.append(get_headers(host, port, True, timeout))
        elif port in HTTP_PORTS:
            http.append(get_headers(host, port, False, timeout))
    findings = analyze(host, port_results, http, tls)
    return {
        "schema_version": 1, "tool": "VulnScope 1.0", "kind": "live-local-scan",
        "target": host, "started_at_utc": clock,
        "duration_seconds": round(time.monotonic() - started, 3),
        "configuration": {"ports": chosen, "timeout_seconds": timeout, "workers": workers,
                          "authorization_acknowledged": True},
        "ports": port_results, "services": services, "http": http, "tls": tls,
        "scan_incomplete": scan_incomplete,
        "findings": findings,
        "severity_counts": {severity: sum(f["severity"] == severity for f in findings) for severity in SEVERITIES},
        "methodology": "Authorized IP-only TCP connect checks; passive banner sampling; HEAD / on known HTTP ports; verified TLS handshake plus clearly labeled untrusted certificate diagnostics.",
        "limitations": ("SCAN INCOMPLETE: service checks stopped at runtime budget. " if scan_incomplete else "") + "Only configured ports and a single HTTP root response are checked. Service names are inferred from ports, not authenticated. No exploitation, CVE confirmation, weak-cipher enumeration, authentication, or subnet discovery. A clean scan does not establish system security.",
    }
