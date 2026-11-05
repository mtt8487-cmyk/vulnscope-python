"""Controlled loopback lab: three tiny HTTP services, HTTPS, and TCP banner.

Usage: python demo_lab.py  (Ctrl+C stops all lab services)
All servers bind 127.0.0.1 and never accept LAN/public clients.
"""
from __future__ import annotations
import ipaddress
import socketserver
import ssl
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Thread
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

LOOPBACK = "127.0.0.1"


class LabHandler(BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        # Intentional variations are header-policy training examples, not exploits.
        if self.server.server_port == 8767:
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:8766/")
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=UTF-8")
        if self.server.server_port == 8766:
            self.send_header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        if self.command == "GET":
            self.wfile.write(b"<html><body><h1>VulnScope controlled local lab</h1></body></html>")

    def log_message(self, fmt, *args):
        return  # No HTTP request logging or client input retained.


class LocalHTTPServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        # TCP-only reachability checks can close before sending HTTP.
        # This is expected and not a lab crash.
        return


class BannerHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.sendall(b"VulnScope controlled TCP test service\r\n")


class BannerServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def make_lab_cert(folder: Path) -> tuple[Path, Path]:
    """Fresh, intentionally untrusted localhost-only TLS identity (not committed)."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder()
        .subject_name(subject).issuer_name(issuer).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=7))
        .add_extension(x509.SubjectAlternativeName([
            x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address(LOOPBACK))]), critical=False)
        .sign(key, hashes.SHA256()))
    cert_path, key_path = folder / "lab.crt", folder / "lab.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return cert_path, key_path


@contextmanager
def lab_servers():
    servers = []
    threads = []
    with tempfile.TemporaryDirectory(prefix="vulnscope-lab-") as temporary:
        try:
            for port in (8765, 8766, 8767):
                server = LocalHTTPServer((LOOPBACK, port), LabHandler)
                servers.append(server)
            cert_path, key_path = make_lab_cert(Path(temporary))
            https = LocalHTTPServer((LOOPBACK, 8768), LabHandler)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(str(cert_path), str(key_path))
            https.socket = ctx.wrap_socket(https.socket, server_side=True)
            servers.append(https)
            banner = BannerServer((LOOPBACK, 8770), BannerHandler)
            servers.append(banner)
            for server in servers:
                thread = Thread(target=server.serve_forever, daemon=True)
                thread.start()
                threads.append(thread)
            yield servers
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)


if __name__ == "__main__":
    with lab_servers():
        print("VulnScope lab listening on 127.0.0.1:8765, 8766, 8767 (HTTP), 8768 (HTTPS), 8770 (TCP).")
        print("HTTPS uses a TEMPORARY self-signed lab certificate; a trust warning is expected.")
        print("Press Ctrl+C to stop all services.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Lab stopped.")
