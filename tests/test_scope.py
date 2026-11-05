import pytest
from vulnscope.scope import parse_ip, authorize, parse_ports, allowed_targets


def test_localhost_normalized():
    assert parse_ip("localhost") == "127.0.0.1"


def test_ip_loopback():
    assert parse_ip("127.0.0.1") == "127.0.0.1"

@pytest.mark.parametrize("target", ["google.com", "http://127.0.0.1", "8.8.8.8", "169.254.0.1", "0.0.0.0", "224.0.0.1"])
def test_forbidden_targets(target):
    with pytest.raises(ValueError):
        parse_ip(target)

def test_private_ip_requires_allowlist():
    with pytest.raises(PermissionError):
        authorize("192.168.1.55", True, {"127.0.0.1"})

def test_authorization_required():
    with pytest.raises(PermissionError):
        authorize("127.0.0.1", False)

def test_localhost_authorized():
    assert authorize("127.0.0.1", True) == "127.0.0.1"

def test_parse_ports():
    assert parse_ports("443,80,8000-8002,80") == [80, 443, 8000, 8001, 8002]

@pytest.mark.parametrize("entry", ["0", "65536", "1-35", "1-65535", "22,,80", "-1", "80:443", ""])
def test_ports_invalid(entry):
    with pytest.raises(ValueError):
        parse_ports(entry)

def test_env_additional_private(monkeypatch):
    monkeypatch.setenv("VULNSCOPE_ALLOWED_TARGETS", "192.168.1.10")
    assert "192.168.1.10" in allowed_targets()

def test_env_public_rejected(monkeypatch):
    monkeypatch.setenv("VULNSCOPE_ALLOWED_TARGETS", "1.1.1.1")
    with pytest.raises(ValueError):
        allowed_targets()
