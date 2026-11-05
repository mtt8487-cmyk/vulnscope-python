"""Verified TLS handshake plus explicitly labeled untrusted certificate inspection."""
import socket
import ssl
from datetime import datetime, timezone
from cryptography import x509
from cryptography.hazmat.primitives import serialization


def cert_details(der: bytes, now: datetime | None = None) -> dict:
    cert = x509.load_der_x509_certificate(der)
    moment = now or datetime.now(timezone.utc)
    start, end = cert.not_valid_before_utc, cert.not_valid_after_utc
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": start.isoformat(),
        "not_after": end.isoformat(),
        "days_remaining": (end - moment).days,
        "expired": end < moment,
        "not_yet_valid": start > moment,
        "self_issued": cert.subject == cert.issuer,
    }


def inspect_tls(host: str, port: int, timeout: float) -> dict:
    result = {"port": port, "verified": False, "verification_error": None,
              "protocol": None, "cipher": None, "certificate": None,
              "certificate_authenticated": False, "error": None}
    try:
        # Proper CA trust and hostname/IP matching stay enabled.
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as secure:
                result["verified"] = True
                result["certificate_authenticated"] = True
                result["protocol"] = secure.version()
                negotiated = secure.cipher()
                result["cipher"] = negotiated[0] if negotiated else None
                result["certificate"] = cert_details(secure.getpeercert(binary_form=True))
                return result
    except ssl.SSLCertVerificationError as exc:
        result["verification_error"] = str(exc)[:250]
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:180]}"
        return result

    # For diagnostics ONLY: an unauthenticated certificate cannot prove identity.
    # The scanner never sends HTTP data over this diagnostic connection.
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure:
                result["protocol"] = secure.version()
                negotiated = secure.cipher()
                result["cipher"] = negotiated[0] if negotiated else None
                result["certificate"] = cert_details(secure.getpeercert(binary_form=True))
    except (OSError, ssl.SSLError, ValueError) as exc:
        result["error"] = f"Diagnostic TLS failed: {type(exc).__name__}: {str(exc)[:120]}"
    return result
