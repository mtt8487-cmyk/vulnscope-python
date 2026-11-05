"""Reports use observed scan data only. Escaping prevents HTML injection."""
import csv
import io
import json
import html
from datetime import datetime


def json_report(scan: dict) -> bytes:
    return json.dumps(scan, indent=2, ensure_ascii=False).encode("utf-8")


def csv_report(scan: dict) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=["id", "title", "severity", "target", "port", "description", "evidence", "impact", "remediation", "reference", "limitations"])
    writer.writeheader()
    # Mitigate CSV formula injection when untrusted evidence is opened in Excel.
    def safe_csv_cell(value):
        if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
            return "'" + value
        return value
    for finding in scan.get("findings", []):
        writer.writerow({name: safe_csv_cell(finding.get(name, "")) for name in writer.fieldnames})
    return out.getvalue().encode("utf-8-sig")


def html_report(scan: dict) -> bytes:
    e = lambda value: html.escape(str(value), quote=True)
    counts = scan.get("severity_counts", {})
    rows = "".join(
        "<tr>" + "".join(f"<td>{e(f.get(key, ''))}</td>" for key in (
            "id", "severity", "title", "port", "evidence", "impact", "remediation", "limitations")) + "</tr>"
        for f in scan.get("findings", [])
    )
    ports = "".join(f"<tr><td>{e(p['port'])}</td><td>{e(p['state'])}</td><td>{e(p['detail'])}</td></tr>" for p in scan.get("ports", []))
    services = "".join(f"<tr><td>{e(s.get('port'))}</td><td>{e(s.get('hint'))}</td><td>{e(s.get('confidence'))}</td><td>{e(s.get('evidence'))}</td></tr>" for s in scan.get("services", []))
    http_info = "".join(f"<tr><td>{e(h.get('port'))}</td><td>{e(h.get('scheme'))}</td><td>{e(h.get('status'))}</td><td>{e(h.get('error'))}</td></tr>" for h in scan.get("http", []))
    tls_info = "".join(f"<tr><td>{e(t.get('port'))}</td><td>{e(t.get('verified'))}</td><td>{e(t.get('protocol'))}</td><td>{e(t.get('cipher'))}</td><td>{e(t.get('verification_error'))}</td></tr>" for t in scan.get("tls", []))
    page = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><title>VulnScope Assessment</title>
<style>body{{background:#0b1220;color:#e5edf8;font:15px Arial,sans-serif;max-width:1150px;margin:40px auto;padding:0 20px}}
h1{{color:#56b6fa}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{border:1px solid #344356;padding:9px;vertical-align:top;text-align:left;word-break:break-word}}
th{{background:#15253b}}.muted{{color:#b0bed0}}.summary{{padding:16px;border:1px solid #364b68;border-radius:9px}}</style></head>
<body><h1>VulnScope | Security Assessment</h1><p class="muted">Recorded observations, not proof of complete security.</p>
<section class="summary"><p><strong>Target:</strong> {e(scan.get('target',''))}</p>
<p><strong>Origin:</strong> {e(scan.get('kind',''))}</p><p><strong>Started (UTC):</strong> {e(scan.get('started_at_utc',''))}</p>
<p><strong>Duration:</strong> {e(scan.get('duration_seconds',''))} seconds</p>
<p><strong>Ports selected:</strong> {e(scan.get('configuration',{}).get('ports',[]))}</p>
<p><strong>Severity counts:</strong> {e(counts)}</p></section>
<h2>TCP Findings</h2><table><thead><tr><th>Port</th><th>State</th><th>Evidence</th></tr></thead><tbody>{ports}</tbody></table>
<h2>Service identification (hints, not proof)</h2><table><thead><tr><th>Port</th><th>Hint</th><th>Confidence</th><th>Observed banner</th></tr></thead><tbody>{services}</tbody></table>
<h2>HTTP observations</h2><table><thead><tr><th>Port</th><th>Scheme</th><th>Status</th><th>Error</th></tr></thead><tbody>{http_info}</tbody></table>
<h2>TLS observations</h2><table><thead><tr><th>Port</th><th>Verified</th><th>Protocol</th><th>Cipher</th><th>Validation error</th></tr></thead><tbody>{tls_info}</tbody></table>
<h2>Security Findings</h2><table><thead><tr><th>ID</th><th>Severity</th><th>Title</th><th>Port</th><th>Evidence</th><th>Potential impact</th><th>Remediation</th><th>Limitations</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Methodology</h2><p>{e(scan.get('methodology',''))}</p><h2>Limitations</h2><p>{e(scan.get('limitations',''))}</p>
<p class="muted">Authorized, scope-limited sampling only; this report is not a comprehensive penetration test.</p>
</body></html>'''
    return page.encode("utf-8")
