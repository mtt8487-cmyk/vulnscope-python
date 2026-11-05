import csv
import io
import json
from vulnscope.reporting import json_report, csv_report, html_report

SCAN = {"target": "127.0.0.1", "started_at_utc": "2026-11-05T00:00:00+00:00", "duration_seconds": 0.1,
        "kind": "recorded-local-lab-scan", "configuration": {"ports": [80]},
        "severity_counts": {"Low": 1}, "ports": [{"port": 80, "state": "open", "detail": "connected"}],
        "findings": [{"id": "F", "title": "<script>alert(1)</script>", "severity": "Low", "target": "127.0.0.1",
        "port": 80, "description": "test", "evidence": "<x>", "impact": "safe", "remediation": "fix",
        "reference": "https://example.invalid", "limitations": "context"}],
        "methodology": "sample", "limitations": "not comprehensive"}


def test_json_round_trip():
    assert json.loads(json_report(SCAN))["target"] == "127.0.0.1"

def test_csv_report():
    rows = list(csv.DictReader(io.StringIO(csv_report(SCAN).decode("utf-8-sig"))))
    assert rows[0]["id"] == "F"

def test_html_escapes_untrusted_evidence():
    markup = html_report(SCAN).decode()
    assert "&lt;script&gt;" in markup and "<script>" not in markup

def test_html_includes_methodology():
    assert "not comprehensive" in html_report(SCAN).decode()


def test_csv_formula_injection_is_escaped():
    altered = dict(SCAN)
    altered["findings"] = [dict(SCAN["findings"][0], evidence="=HYPERLINK(\"bad\")")]
    rows = list(csv.DictReader(io.StringIO(csv_report(altered).decode("utf-8-sig"))))
    assert rows[0]["evidence"].startswith("'=HYPERLINK")
