# VulnScope — Internship Resume and Interview Preparation

Use these statements only after checking the implementation yourself. Add a hosted-demo URL only after your public `public_app.py` deployment actually works.

## ATS-friendly project entry

**VulnScope — Python Vulnerability Scanner | Python, Streamlit, TCP/IP, TLS, pytest | November 2026**

- Developed an authorization-gated Python network assessment tool that performs bounded TCP connect scans, service-hint identification, and read-only HTTP/TLS configuration checks against explicitly allowlisted systems.
- Engineered an evidence-based findings pipeline with severity classification, verification limitations, remediation guidance, and downloadable JSON, CSV, and HTML security assessment reports.
- Built a Streamlit assessment dashboard, isolated read-only public demo, reproducible localhost test environment, and automated tests covering scope controls, scan behavior, HTTP/TLS checks, and reporting.

**After independently verifying on your machine**, you can mention a verified numeric test count (50 in the packaged build). Do not claim Windows/browser/deployment validation until completed.

## Concise recruiter explanation

"VulnScope is a Python cybersecurity project that evaluates basic network and web security configurations. It can connect to authorized TCP ports, inspect selected HTTP headers and TLS certificates, and generate a prioritized report with evidence and remediation advice. I built a separate read-only Streamlit demo so recruiters can explore real recorded lab results without performing live scans."

## 30-second elevator pitch

"I built VulnScope to practice the actual vulnerability management workflow, not just port scanning. It's a Python tool that first enforces an allowlist and target authorization, then checks TCP connectivity, selected web security headers, and TLS trust. It maps observed issues to explainable severity ratings and produces downloadable reports. I tested it against a controlled localhost lab and created a separate recruiter demo that can only display historical scan data. The project taught me how to handle false positives and scope restrictions in security automation."

## Technical interview walkthrough (~2 minutes)

1. **Architecture:** `scope.py` rejects DNS/public targets, then `network.py` executes bounded TCP connect checks. `scanner.py` orchestrates protocol-specific checks and `findings.py` translates supported evidence into findings.
2. **Reliability:** ports are capped at 32; workers at 8; TCP connect timeout defaults to 0.75 seconds. No ICMP assumption, packets crafted, stealth scanning, or credential collection.
3. **Network interpretation:** a successful connect only means TCP handshake succeeded on that address/port at that moment; banners and well-known ports are not reliable version fingerprints.
4. **HTTP/TLS:** the scanner issues one HEAD request to selected HTTP ports without following redirects; TLS trust and hostname/IP verification remain on, and untrusted certificate inspection is explicitly flagged diagnostic-only.
5. **False positives:** missing headers are contextual, e.g., CSP framing checks are applied when an HTML response is observed; no CVEs or CVSS ratings are invented.
6. **Defensible demonstration:** five captured local-lab scenarios show reproducible observations; the public Streamlit app imports only precomputed fixtures, never the scan engine.
7. **Reporting:** CSV is a findings list, JSON contains the full capture, and HTML escapes all displayed evidence.

## Five realistic interview questions and suggested answers

**1. Does an open TCP port mean there is a vulnerability?**

No. An open port proves that a TCP connection was accepted. A security issue depends on which service is running, how it is configured, exposure, permissions, and patch state. My scanner treats reachability as evidence, not an exploit confirmation.

**2. Why did you use TCP connect scans instead of raw SYN scans?**

TCP connect works through Python's standard socket API without administrator privileges or packet-crafting dependencies. It is easy to understand, bounded, and sufficient for this entry-level assessment. It is not stealthy; that is intentional.

**3. What do you do if the TLS certificate is self-signed?**

The normal verified TLS handshake fails, and I report the trust failure. I can make a separate explicitly untrusted, read-only diagnostic TLS connection solely to parse the presented certificate dates and algorithm information; I never label that identity as authenticated or send HTTP requests through it.

**4. How does your scanner avoid making ungrounded vulnerability claims?**

It only triggers documented rules from actual network, HTTP, or TLS observations and includes an evidence statement and limitations for every finding. I don't infer exploitable CVEs from software banners, and I distinguish low-risk configuration signals from verified high-impact defects.

**5. How did you prevent your deployed demo from scanning arbitrary websites?**

The hosted entrypoint is a separate Python application (`public_app.py`) which loads packaged JSON lab results and the display component only. It does not import scanning modules or accept targets. The actual scanning app is intentionally only used locally with exact-IP allowlisting and an authorization checkbox.

## Skills to list

Python 3.11, Network Security, TCP/IP, Socket Programming, TLS/SSL, HTTP Security Headers, Security Configuration Assessment, Vulnerability Management, Secure Input Validation, Software Testing (pytest), Streamlit, Git/GitHub, JSON, CSV, HTML Reporting, Security Automation.

## GitHub and public demo links

In the resume project title, link the project name to your real `https://github.com/YOUR-USERNAME/vulnscope-python` repository. When Phase 11 is successful, add **Demo: your actual Streamlit Community Cloud URL**. Never leave the placeholder links in the final resume.

## Recommended screenshots

1. Local live-scan configuration with authorization checkbox (no sensitive targets).
2. A real completed localhost multi-port assessment showing metrics and table.
3. A security finding expanded with evidence, impact, remediation, and limitation.
4. A downloaded HTML example assessment.
5. Public read-only demo's historical-scan selector.

Capture via Windows `Win+Shift+S`; save PNGs to `screenshots/`, then commit. Never include private IPs outside your approved lab, credentials, real customer findings or personal data.

## LinkedIn project description

"Built VulnScope, a Python network security assessment application for authorized systems. Implemented bounded TCP connect scanning, basic service identification, HTTP security-header checks, TLS certificate validation, evidence-based risk findings, and downloadable reports. Developed a dark-themed Streamlit interface with a separately isolated read-only public demo and reproducible local lab tests. Focused on minimizing false positives, authorization safeguards, and explaining remediation clearly."

## Highest-value next improvements

| Difficulty | Impact | Enhancement | Why it matters |
|---|---|---|---|
| Easy | High | GitHub Actions CI across Python 3.11 and 3.12 | Continuous cross-version regression testing |
| Easy | High | Real dashboard screenshots and deployed public sample explorer | Stronger recruiter discoverability |
| Medium | High | Parse configurable HTTP ports without unsafe autodiscovery | More flexible lab assessments |
| Medium | High | Add explicit TLS SAN visualization with authenticated/untrusted status | Better certificate assessment detail |
| Medium | Medium | Add rule-ID-based risk acceptance and comparison between two saved scans | Practical vulnerability management workflow |
| Hard | High | Reliably identify installed software via authenticated asset inventory before CVE correlation | Avoid unsupported CVE guesses |
| Hard | Medium | Add scan cancellation with cooperative nonblocking sockets and a strict global deadline | Better production-grade resource management |

No current feature is a substitute for an authorized professional penetration test or complete vulnerability scan.
