from vulnscope.findings import analyze_http, analyze_tls, analyze_exposure, RUBRIC


def base_http(headers=None, scheme="http", status=200):
    return {"port": 8765, "scheme": scheme, "status": status, "headers": headers or {}, "error": None, "redirect": None}


def test_missing_headers_on_html():
    ids = [x["id"] for x in analyze_http("127.0.0.1", base_http({"content-type": "text/html"}))]
    assert {"HTTP-XCTO", "HTTP-CSP", "HTTP-FRAME"}.issubset(ids)

def test_hardened_html():
    h = {"content-type": "text/html", "content-security-policy": "frame-ancestors 'none'; default-src 'none'", "x-content-type-options": "nosniff"}
    assert not analyze_http("127.0.0.1", base_http(h))

def test_json_no_clickjacking_flag():
    ids = [x["id"] for x in analyze_http("127.0.0.1", base_http({"content-type": "application/json"}))]
    assert "HTTP-CSP" not in ids and "HTTP-FRAME" not in ids

def test_https_hsts():
    ids = [x["id"] for x in analyze_http("127.0.0.1", base_http({"content-type": "text/html"}, "https"))]
    assert "HTTP-HSTS" in ids

def test_http_error_no_findings():
    data = base_http(); data["error"] = "connection refused"
    assert analyze_http("127.0.0.1", data) == []

def test_server_header_informational():
    output = analyze_http("127.0.0.1", base_http({"server": "ExampleServer", "x-content-type-options": "nosniff"}))
    assert any(f["id"] == "HTTP-BANNER" and f["severity"] == "Informational" for f in output)

def test_redirect_not_followed():
    data = base_http(); data["status"] = 302; data["redirect"] = "https://elsewhere.invalid/"
    assert any(f["id"] == "HTTP-REDIRECT" for f in analyze_http("127.0.0.1", data))

def test_tls_trust_failure_medium():
    x = {"port": 8768, "verified": False, "verification_error": "self-signed certificate", "certificate": None, "protocol": "TLSv1.3"}
    assert analyze_tls("127.0.0.1", x)[0]["severity"] == "Medium"

def test_tls_clean_no_findings():
    assert analyze_tls("127.0.0.1", {"port": 443, "verified": True, "verification_error": None, "certificate": None, "protocol": "TLSv1.3"}) == []

def test_old_negotiated_tls():
    a = analyze_tls("127.0.0.1", {"port": 443, "protocol": "TLSv1.1", "certificate": None, "verification_error": None})
    assert any(f["id"] == "TLS-OLD" for f in a)

def test_open_port_not_automatically_vulnerable():
    assert analyze_exposure("127.0.0.1", [{"port": 8080, "state": "open"}]) == []

def test_remote_management_informational():
    a = analyze_exposure("127.0.0.1", [{"port": 3389, "state": "open"}])
    assert len(a) == 1 and a[0]["severity"] == "Informational"

def test_severity_rubric_present():
    assert len(RUBRIC) == 5
