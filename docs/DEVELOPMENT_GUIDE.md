# VulnScope — Detailed 12-Phase Windows 11 Development Walkthrough

**Audience:** college IT/cybersecurity student using Windows 11, VS Code, Python 3.11, PowerShell, and Git. The project ZIP contains the **complete source code** for every file, so no code has to be invented or copied from a tutorial. Follow phases in order and keep the filenames unchanged. Local app uses genuine data; public demo displays historical captures only.

**Working directory convention:** `%USERPROFILE%\Documents\vulnscope-python`. If your extraction is elsewhere, replace this absolute path consistently. All commands below assume PowerShell opened in the extracted `vulnscope-python` folder unless otherwise stated. Prefix `./` not required for Python because we use an explicit interpreter path.

## Phase 1 — Install and verify the tools

**Objective:** Install Python 3.11, VS Code and Git. **Open:** Windows PowerShell (Start menu). **Required files:** none yet. **Commands:**

```powershell
winget --version
winget install --id Python.Python.3.11 -e
winget install --id Microsoft.VisualStudioCode -e
winget install --id Git.Git -e
```

Installers may say they are already installed; that is fine. Close and reopen PowerShell so PATH is refreshed:

```powershell
py -3.11 --version
code --version
git --version
```

**Expected:** a `Python 3.11.x` version, a VS Code version and `git version x.y.z`. VS Code: open **Extensions** (`Ctrl+Shift+X`), install the Microsoft **Python** and **Pylance** extensions. Nothing else is required; do not separately install OpenSSL or Nmap. **Next command:** `py -3.11 --version`. **Troubleshooting:** If `py` not found, rerun the installer with Python Launcher enabled or use the Python 3.11 installer at python.org; restart PowerShell. If `code` not found, open VS Code directly via Start and choose **File → Open Folder** later. If `winget` unavailable, use the official product installers. **Checkpoint:** all three version commands work.

## Phase 2 — Extract the source files and install packages

**Objective:** Open the complete ready-to-run project and create its virtual environment. **Open:** File Explorer → extract the ZIP into `Documents`, then VS Code → File → Open Folder → `Documents\vulnscope-python`. Use VS Code **Terminal → New Terminal** (PowerShell). The ZIP already contains full implementations of `app.py`, `public_app.py`, `cli.py`, `demo_lab.py`, `record_demos.py`, `vulnscope/*.py`, tests, `.streamlit/config.toml`, documentation and recorded demo fixtures.

```powershell
cd "$HOME\Documents\vulnscope-python"
Get-ChildItem
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe --version
```

**Expected:** `Python 3.11.x`, successful package installation, and `.venv` folder. Select VS Code Python interpreter: `Ctrl+Shift+P` → **Python: Select Interpreter** → `...\vulnscope-python\.venv\Scripts\python.exe`. We deliberately run `.venv\Scripts\python.exe` directly to avoid PowerShell execution-policy errors. **Next:** ` .\.venv\Scripts\python.exe -m pytest -q` (without leading space). **Troubleshooting:** If the project folder is nested twice (`vulnscope-python\vulnscope-python`), open the inner folder containing `app.py`. If Windows `Access denied`, use a user-writable Documents directory. If Python 3.11 missing, finish Phase 1. **Checkpoint:** `requirements-dev.txt` installs and the Python interpreter is 3.11.

## Phase 3 — Core TCP scanning and strict target scope

**Objective:** Understand and validate the functioning TCP connect scanner. **Open:** VS Code Explorer. **Read source files:** `vulnscope/scope.py` (target validation, port limits) → `vulnscope/network.py` (TCP connect in bounded worker pool) → `vulnscope/scanner.py` (orchestrator). **Nothing to paste:** the full files are present, with executable implementations and type-aware function signatures.

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_scope.py tests\test_network_and_tls.py -q
.\.venv\Scripts\python.exe cli.py --target 127.0.0.1 --ports 8765 --authorized
```

**Expected:** test pass summary. Without the lab running, TCP/8765 will usually show `refused` and the CLI writes `reports/` files. That is an authentic reachability observation, not a defect. `ConnectionRefused` means a target replied to the TCP SYN with an active refusal; `timeout` usually means no connect response within deadline; `open` means a TCP handshake completed, not that the application is secure. **Next:** `.\.venv\Scripts\python.exe demo_lab.py`. **Troubleshooting:** `Target is not on exact-IP allowlist` means you have not configured an extra private target; use localhost first. The scanner rejects public IPs by design. **Checkpoint:** scope tests pass and a local `reports/assessment.json` is produced.

## Phase 4 — Service identification

**Objective:** Show why observed evidence differs from a port association. **Open:** `vulnscope/services.py` and `vulnscope/config.py`. Hints (e.g., TCP/22 = SSH) are marked *inferred*. Short banners are collected only on a small set of protocols that send a greeting; banners are not authenticated software versions.

**Terminal 1:**

```powershell
cd "$HOME\Documents\vulnscope-python"
.\.venv\Scripts\python.exe demo_lab.py
```

**Terminal 2:**

```powershell
cd "$HOME\Documents\vulnscope-python"
.\.venv\Scripts\python.exe cli.py --ports 8765-8770 --authorized
```

**Expected:** the controlled services respond on 8765, 8766, 8767, 8768 and 8770; port 8769 is intentionally not served. Inspect `reports/assessment.json` → `services` where the common HTTP/HTTPS ports have **hints**, not proof of a named server. **Next:** inspect `vulnscope/http_checks.py` and `vulnscope/tls_checks.py`. **Troubleshooting:** If `WinError 10048`, another process occupies a lab port; stop it before starting the lab. **Checkpoint:** open/closed ports and service hints are visible.

## Phase 5 — HTTP and TLS checks

**Objective:** Assess defensible observations from the controlled lab. **Open:** `vulnscope/http_checks.py` (single direct `HEAD /`, redirects never followed); `vulnscope/tls_checks.py` (CA-trusted handshake, certificate parsing). **Command:** with lab running, rerun:

```powershell
.\.venv\Scripts\python.exe cli.py --ports 8765-8768 --authorized
```

**Expected:** the first HTTP service lacks important defense-in-depth headers; the hardened service supplies CSP, nosniff and framing protection; the local redirect is recorded but not followed; TLS/8768 presents a temporary self-signed certificate, so trust validation fails *as expected*. Inspection of the presented certificate is labeled *unauthenticated diagnostic only*. **Next:** open `reports/assessment.html` in a browser. **Troubleshooting:** A failed HTTPS `HEAD` check for the self-signed lab is correct—VulnScope does not disable validation to fetch the webpage. Verify `127.0.0.1` target and that the local lab remains running. **Checkpoint:** at least one observed HTTP weakness and a trust finding appear in `assessment.json`.

## Phase 6 — Rule-based findings and severity

**Objective:** Convert observations to explainable findings. **Open:** `vulnscope/findings.py`. It contains the full severity rubric, observed evidence, risk, remediation, limitation and authoritative reference for each rule; no CVE is fabricated. **Command:**

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_findings.py -q
```

**Expected:** passing tests. An open port alone is not labeled a vulnerability. A self-signed lab certificate triggers a **Medium** trust finding, not a fictional Critical CVE. **Next:** open `vulnscope/ui.py` and `app.py`. **Troubleshooting:** If a service appears as `Unknown`, that is intentional whenever the identity cannot be verified. **Checkpoint:** tests pass and every finding contains evidence and limitations.

## Phase 7 — Professional local Streamlit dashboard

**Objective:** Use the UI to launch actual local scans. **Open:** VS Code, `app.py`, `vulnscope/ui.py` and `.streamlit/config.toml`. With the lab still running in Terminal 1, start Terminal 2:

```powershell
.\.venv\Scripts\python.exe -m streamlit run app.py
```

**Expected:** Streamlit opens an address normally like `http://localhost:8501` (the actual port is the one printed by Streamlit). In the **Run authorized local scan** tab, enter `127.0.0.1`, port range `8765-8770`, leave default timeout/workers, check the authorization box, click **Start authorized scan**. Read metrics, chart, open-port table, evidence, remediation, and severity filters. The separate tab shows labeled historical captures. **Next:** click the three report download buttons. **Troubleshooting:** If `streamlit` is missing, repeat Phase 2 install. If it opens a different port, use the terminal URL. If blank, check browser dev tools and Python traceback in terminal. **Checkpoint:** live results actually reflect the running lab and three downloads work.

## Phase 8 — Security assessment reporting

**Objective:** Produce a manager-readable HTML report plus machine-readable JSON and CSV. **Open:** `vulnscope/reporting.py` and browser. **Command:** with lab running:

```powershell
.\.venv\Scripts\python.exe cli.py --ports 8765-8770 --authorized
Invoke-Item .\reports\assessment.html
.\.venv\Scripts\python.exe -m pytest tests\test_reporting.py -q
```

**Expected:** `reports/assessment.html`, `reports/assessment.json`, `reports/findings.csv`. HTML displays target, timestamp, duration, scanned ports, service observations, HTTP/TLS summary, severity totals, findings, methodology and limitations; JSON contains complete raw observations; CSV is a findings export. **Next:** `.\.venv\Scripts\python.exe -m pytest -q`. **Troubleshooting:** if reports appear unchanged, rerun CLI with lab active and use browser Refresh. All private reports stay inside Git-ignored `reports/`. **Checkpoint:** HTML renders without allowing raw untrusted HTML in evidence.

## Phase 9 — Real local lab + automated tests

**Objective:** Verify end-to-end behavior and regenerate five nonfabricated demo captures. **Open:** `demo_lab.py`, `record_demos.py`, and `tests/`. Stop the manually running lab with `Ctrl+C` first—`record_demos.py` temporarily starts the same fixed ports itself.

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe record_demos.py
Get-ChildItem .\samples\lab-*.json
```

**Expected:** all tests pass (50 in the packaged build) and exactly five JSON files are regenerated with fresh UTC timestamps. Samples are labeled `recorded-local-lab-scan` and contain genuine TCP/HTTP/TLS measurements. The lab certificate is temporary and not committed. **Next:** `git status`. **Troubleshooting:** if a port is already in use, stop the independent `demo_lab.py` terminal, then retry. Never edit sample JSON to invent findings. **Checkpoint:** all tests pass and five recorded fixtures exist.

## Phase 10 — Polish, document, and publish on GitHub

**Objective:** Publish only source, tests and safe historical loopback fixtures. **Open:** `README.md`, `.gitignore`, `LICENSE`, GitHub website, and VS Code terminal. Review the files first:

```powershell
git status
git init
git branch -M main
git add .
git status --short
git check-ignore .venv reports .env
```

**Expected:** `.venv`, `reports/` and `.env` are ignored; source and `samples/` may be added. If git identity unknown, configure your own identity with `git config --global user.name "YOUR NAME"` and `git config --global user.email "YOUR_GITHUB_EMAIL"` (these two values are personal details you must supply). Then:

```powershell
git commit -m "Build VulnScope authorized vulnerability assessment platform"
```

On https://github.com/new create a **public, empty repository** named **`vulnscope-python`** (do **not** initialize it with another README or license). Copy the exact repository URL shown on GitHub. Back in PowerShell, substitute **your actual GitHub repository URL**:

```powershell
git remote add origin https://github.com/YOUR-USERNAME/vulnscope-python.git
git push -u origin main
```

**Expected:** Git push completes and the repository displays `README.md`, Python modules, tests, `samples`, and docs. Add dashboard screenshots *after capturing them yourself* by saving PNGs in `screenshots/`, then:

```powershell
git add screenshots README.md
git commit -m "Add live dashboard screenshots"
git push
```

**Pin:** GitHub profile → **Customize your pins** → select the repository → Save. **Troubleshooting:** if remote exists, use `git remote -v`; if authentication fails, GitHub may ask you to sign in through Git Credential Manager. GitHub account passwords cannot be used as Git push credentials. **Checkpoint:** public repository opens and no `.venv`, secrets, private scans or lab private keys have been pushed.

## Phase 11 — Public safe read-only Streamlit deployment

**Objective:** Host recruiters' demo without enabling scanning. **Open:** https://share.streamlit.io or Streamlit Community Cloud via https://streamlit.io/cloud. Sign in with GitHub and choose **Create app → Deploy a public app from GitHub**. Set repository to `YOUR-USERNAME/vulnscope-python`, branch `main`, and **Main file path: `public_app.py`**. In **Advanced settings**, choose Python **3.11** if available. No secrets or external packages are needed beyond `requirements.txt`. Deploy.

**Expected:** a Streamlit public URL (assigned by the platform, so not predictable). Check the page title **VulnScope — Security Assessment Explorer**, the demo case selector, five labeled historical cases, details, severity filters, and download buttons. Verify there is **no target field and no Start Scan button**. The public entrypoint does not import the scanner or perform any network requests. Do **not** deploy `app.py`. For additional protection, configure `VULNSCOPE_PUBLIC_DEMO=1` if running the local entrypoint in any hosted environment. **Next:** test each saved scenario and copy your actual URL. **Troubleshooting:** if `ModuleNotFoundError`, confirm requirements and `public_app.py` in repository root; inspect Streamlit build logs. If the Python version differs from local, adjust Advanced settings or redeploy. **Checkpoint:** public URL works as a read-only demonstration, and has no live-scan controls.

## Phase 12 — Internship resume and interviews

**Objective:** Explain verified achievements without exaggerating testing results. **Open:** your resume in Word and `docs/INTERVIEW_PREP.md`. Add your actual GitHub and deployed demo URLs only after Phase 10/11 are complete. Use three resume bullets, the 30-second explanation, Q&A and screenshot checklist from that guide. **Next:** capture real dashboard screenshots and update your resume; **expected result** is a portfolio project you can substantiate in an interview. **Troubleshooting:** if you have not deployed yet, link only the public GitHub repository; do not invent a live URL. **Checkpoint:** portfolio and resume descriptions match implemented features.

## Operational limits and common problems

- **Port != vulnerability:** a reachable TCP service can be intentionally deployed and secured.
- **Localhost only by default:** only an exact private lab IP explicitly present in `VULNSCOPE_ALLOWED_TARGETS` may be added; never run against systems without permission.
- **DNS rebinding:** prevented by refusing arbitrary hostname resolution; only `localhost` (mapped to `127.0.0.1`) and numeric IP literals are accepted.
- **Redirects:** observed but never followed; an external target cannot be reached by an HTTP redirect.
- **TLS authentication:** the application never marks a diagnostic, unverifiable certificate as trusted. Public demo only reads static JSON files.
- **Timeouts:** bounded per TCP connection plus an upper assessment stage budget; network conditions can affect total wall-clock duration; a strict hard-kill is not guaranteed for blocking OS operations.
- **Host discovery:** this is direct TCP connect sampling, not ICMP/ping. Lack of open selected ports does not establish that the host is offline.
- **Version/CVE mapping:** not implemented. Port numbers and banners cannot safely justify specific CVEs; use NVD and CISA KEV catalogs manually only after reliable product/version identification.

## References

- [Python 3.11 networking / ssl documentation](https://docs.python.org/3.11/library/ssl.html)
- [OWASP HTTP security response headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)
- [Streamlit Community Cloud deployment documentation](https://docs.streamlit.io/deploy/streamlit-community-cloud/deploy-your-app/deploy)
- [NVD API developer guidance](https://nvd.nist.gov/developers)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
