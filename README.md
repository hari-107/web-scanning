# WebSec Scanner — Web Security Assessment Platform

A Django-based platform that runs an automated, multi-stage security
assessment against a target website: reconnaissance, discovery, and
non-destructive vulnerability testing, correlated into a professional report
with a PDF export. No authentication, no AI services, no Docker.

> **Authorised use only.** This tool sends active probes (injection payloads,
> port scans, directory brute-forcing). Only scan systems you own or have
> explicit written permission to test. A consent checkbox gates every scan.

## Features

- **Dashboard** — total scans, findings, active scans, average score, severity
  distribution and risk-rating charts, recent scans and high-risk findings.
- **One-click scan** — enter a URL, confirm authorisation, click *Start Scan*.
- **Live progress** — real-time phase, progress bar, elapsed/ETA, request and
  URL counters, and a streaming execution log.
- **Sequential pipeline** (fault-tolerant — one module failing never aborts the run):
  1. Reconnaissance — DNS/IP, server & OS fingerprint, response & security
     headers, cookies, robots.txt, sitemap.xml
  2. SSL/TLS analysis — protocol, cipher, certificate, deprecated protocols
  3. Technology detection — CMS, frameworks, JS libraries, languages, servers
  4. Port scanning — service & version detection
  5. Directory/file enumeration — admin panels, APIs, backups, `.git`, `.env`…
  6. Crawling — builds the site map, extracts forms and parameters
  7. SQL Injection — error-based, boolean-based, time-based
  8. XSS — reflected and DOM-based
  9. Injection & misconfig — LFI/traversal, command injection, open redirect,
     SSTI, CORS, clickjacking, HTTP methods
  10. Authentication — login SQLi/XSS, CSRF token, rate limiting, username
      enumeration
  11. Server misconfiguration — directory listing, verbose errors
- **Comprehensive report** — findings with severity, CVSS, CWE, evidence,
  proof, payload, impact, remediation, references, and the detecting module;
  plus ports, technologies, endpoints, forms, headers, cookies, SSL, robots and
  sitemap, an overall security score, risk rating and executive summary.
- **Report management** — browse, search by URL/host/IP, filter by severity and
  status, compare scans side by side, rescan, delete, and download PDF.
- **Modular engine** — every scanner is an independent module under
  `scanner/engine/` with a `run(ctx)` entry point, usable standalone or via the
  orchestrator.

## Tool auto-detection with pure-Python fallbacks

External tools are used automatically **when installed**, with a built-in
Python implementation otherwise, so the platform is fully functional with zero
external tools:

| Task                 | Preferred tool        | Fallback                         |
|----------------------|-----------------------|----------------------------------|
| Port scan            | `nmap -sV`            | threaded socket scan + banners   |
| Directory enum       | `ffuf` / `gobuster`   | threaded HTTP wordlist prober    |
| Tech fingerprint     | `whatweb`             | built-in signature engine        |
| Server misconfig     | `nikto`               | built-in misconfiguration checks |
| SSL/TLS              | Python `ssl`          | —                                |

Install the real tools and put them on `PATH` for richer results; the scanner
detects them at runtime with no config change.

## Requirements

- Python 3.11+
- MySQL / MariaDB (e.g. XAMPP)

## Setup

```bash
pip install -r requirements.txt
```

Start MySQL and create the database (XAMPP defaults: user `root`, no password):

```sql
CREATE DATABASE websec CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

Configure DB via environment variables if your setup differs (defaults shown):

```
WEBSEC_DB_NAME=websec  WEBSEC_DB_USER=root  WEBSEC_DB_PASSWORD=
WEBSEC_DB_HOST=127.0.0.1  WEBSEC_DB_PORT=3306
```

Migrate and run:

```bash
python manage.py migrate
python manage.py runserver
```

Open http://127.0.0.1:8000/. (Optional admin: `python manage.py createsuperuser`.)

## Configuration

Scan behaviour is tunable via environment variables (see
`SCAN_SETTINGS` in `websec/settings.py`): `WEBSEC_MAX_CRAWL_PAGES`,
`WEBSEC_MAX_CRAWL_DEPTH`, `WEBSEC_REQUEST_TIMEOUT`, `WEBSEC_HTTP_THREADS`,
`WEBSEC_PORT_THREADS`, `WEBSEC_DIR_WORDLIST_LIMIT`, `WEBSEC_USER_AGENT`.

## Project layout

```
websec/                 Django project (settings, urls, PyMySQL shim)
scanner/
  models.py             Scan, Finding, Port, Technology, Endpoint, Form,
                        HttpHeader, Cookie, LogLine
  views.py, urls.py     dashboard, start, live status, report, list,
                        compare, rescan, delete, PDF
  engine/
    base.py             ScanContext: HTTP session, logging, progress, dedup
    runner.py           secure subprocess exec + tool detection
    validator.py        target validation/normalisation
    recon.py ssl_analysis.py tech.py ports.py dirsearch.py crawler.py
    vulntests/          sqli.py xss.py misc.py auth.py (+ targets.py)
    nikto.py scoring.py orchestrator.py background.py
    payloads.py wordlists.py
  reporting/pdf.py      ReportLab PDF
  templates/ static/    Bootstrap 5 UI, Chart.js, live-progress JS
```

## Notes

- Scans run in a background thread; the database is the single source of truth
  for progress, so multiple browser tabs can poll independently.
- All vulnerability tests are detection-only and non-destructive.
- `Endpoint.url` and `Scan.target_url` are intentionally not DB-indexed/unique
  (they exceed InnoDB's 3072-byte key limit); de-duplication is done in code.
