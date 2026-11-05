import socket
from datetime import datetime, timedelta, timezone
from threading import Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
from vulnscope.network import connect_port
from vulnscope.http_checks import get_headers
from vulnscope.tls_checks import cert_details
from vulnscope.scanner import run_scan



def test_refused_port(monkeypatch):
    def raise_refused(*args, **kwargs):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(socket, "create_connection", raise_refused)

    assert connect_port("127.0.0.1", 12345, 0.3)["state"] == "refused"


def test_timeout_port(monkeypatch):
    def raise_timeout(*args, **kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(socket, "create_connection", raise_timeout)

    assert connect_port("127.0.0.1", 12345, 0.3)["state"] == "timeout"


def test_invalid_scan_timeout():
    with pytest.raises(ValueError):
        run_scan("127.0.0.1", "8765", True, timeout=3)


def test_invalid_workers():
    with pytest.raises(ValueError):
        run_scan("127.0.0.1", "8765", True, workers=40)


def test_scanner_forbidden_target():
    with pytest.raises(ValueError):
        run_scan("8.8.8.8", "443", True)


def test_scanner_consent():
    with pytest.raises(PermissionError):
        run_scan("localhost", "80", False)


def test_scanner_local_socket():
    sock = socket.socket(); sock.bind(("127.0.0.1", 0)); sock.listen(1)
    try:
        port = sock.getsockname()[1]
        result = run_scan("127.0.0.1", str(port), True)
        assert result["ports"][0]["state"] == "open"
        assert result["ports"][0]["port"] == port
        assert result["kind"] == "live-local-scan"
    finally:
        sock.close()


def test_http_local_header_reads_no_external_requests():
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    try:
        result = get_headers("127.0.0.1", server.server_port, False, 0.5)
        assert result["headers"]["x-content-type-options"] == "nosniff"
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_certificate_date_parser():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.now(timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "local")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=2))
        .not_valid_after(now-timedelta(days=1)).sign(key, __import__("cryptography").hazmat.primitives.hashes.SHA256()))
    decoded = cert_details(cert.public_bytes(serialization.Encoding.DER), now)
    assert decoded["expired"] is True and decoded["days_remaining"] < 0
