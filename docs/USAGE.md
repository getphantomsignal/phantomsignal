# PhantomSignal — User Guide

> **Legal reminder:** Only scan targets you own or have explicit written permission to test. Refer to the [Legal & Ethics](../README.md#️-legal--ethics) section in the README before proceeding.

---

## Table of Contents

1. [Getting Started](#1-getting-started)
2. [The Web Interface](#2-the-web-interface)
3. [Launching a Ghost Run](#3-launching-a-ghost-run)
4. [Usage Scenarios](#4-usage-scenarios)
   - [Scenario A — Website Security Audit](#scenario-a--website-security-audit)
   - [Scenario B — IP / Server Reconnaissance](#scenario-b--ip--server-reconnaissance)
   - [Scenario C — Domain Intelligence](#scenario-c--domain-intelligence)
   - [Scenario D — People Intelligence (Shadow Profiler)](#scenario-d--people-intelligence-shadow-profiler)
   - [Scenario E — Bug Bounty Recon](#scenario-e--bug-bounty-recon)
   - [Scenario F — Covert Recon (Low-and-Slow)](#scenario-f--covert-recon-low-and-slow)
5. [Configuring API Keys](#5-configuring-api-keys)
6. [Reading Results](#6-reading-results)
7. [Exporting Intel](#7-exporting-intel)
8. [CLI Usage](#8-cli-usage)
9. [Troubleshooting](#9-troubleshooting)
   - [Linux](#linux)
   - [macOS](#macos)
   - [Windows](#windows)
   - [Docker](#docker)

---

## 1. Getting Started

### Installation (Manual)

```bash
# Requires Python 3.10+
git clone https://github.com/getphantomsignal/phantomsignal
cd phantomsignal
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
python run.py
```

Open **http://127.0.0.1:5000** in your browser.

### Installation (Docker)

```bash
git clone https://github.com/getphantomsignal/phantomsignal
cd phantomsignal
docker-compose up -d
```

Open **http://localhost:5000**.

### First-run checklist

| Step | Action |
|------|--------|
| 1 | Open the web UI at `http://127.0.0.1:5000` |
| 2 | Navigate to **Ghost Keys** (⚙ in nav bar) and add at least one API key |
| 3 | Go back to the **Shadow Grid** dashboard |
| 4 | Use **Quick Probe** or **Launch Ghost Run** to start your first scan |

---

## 2. The Web Interface

### Navigation

| Page | Nav Label | Description |
|------|-----------|-------------|
| Dashboard | **GRID** | Mission overview, live feed, API status, quick probe |
| New Scan | **NEW MISSION** | Full scan configuration form |
| Scan List | **GHOST RUNS** | All past and active missions |
| People Intel | **SHADOW PROFILER** | Person/email/username lookup |
| Settings | **GHOST KEYS** | API key management |

### Theme Switch

Use the **☀ / ☾** segmented control in the top navigation to switch between:
- **Dark** — deep-slate federal console with federal-blue hero, gold accents, and restrained glow (default)
- **Light** — clean, print-friendly theme with white surfaces, federal-blue accents, and no glow

Both themes are built on the same semantic role tokens and validated to WCAG AA contrast. Your preference is saved in the browser, persists across sessions, and is applied before first paint so there's no flash on reload.

### Live Feed

The **LIVE FEED** terminal on the dashboard streams real-time events from any active scan via WebSocket. Events are colour-coded:
- **Cyan** — system/connection messages
- **Green** — successful findings
- **Yellow/Orange** — warnings
- **Red** — errors or high-severity findings

---

## 3. Launching a Ghost Run

### Quick Probe (dashboard)

The fastest way to start — enter a target in the **QUICK PROBE** box on the dashboard. This runs all five default modules (`dns_recon`, `port_scan`, `tech_detect`, `api_hunt`, `intel`) with the quick profile. Results appear in Ghost Runs within seconds.

### Full Ghost Run (New Mission page)

1. Navigate to **NEW MISSION**
2. Enter your target (domain, IP, URL, email, or username)
3. Choose a **Mission Profile**:

| Profile | Duration | Use Case |
|---------|----------|----------|
| **Quick Probe** | ~30 sec | Fast triage, live asset check |
| **Standard Recon** | 2–5 min | Balanced — most common choice |
| **Deep Dive** | 10–30 min | Full crawl, all ports, all APIs |
| **Covert** | Variable | Low-and-slow, minimal footprint |

4. Toggle individual **Recon Modules** on/off as needed
5. Adjust **Advanced Config** (crawl depth, port profile, robots.txt respect)
6. Click **INITIATE GHOST RUN**

You are redirected to the live results page where findings stream in as they're discovered.

---

## 4. Usage Scenarios

### Scenario A — Website Security Audit

**Goal:** Assess the security posture of a web application you own.

**Recommended settings:**
- Target: `https://yoursite.com`
- Profile: **Standard Recon**
- Modules: DNS Recon ✓, Port Scanner ✓, Tech Detector ✓, API Hunter ✓, Web Crawler ✓
- Evasive mode: off

**What PhantomSignal will find:**
- Open ports and exposed services (admin panels, staging, APIs)
- Technology stack (CMS version, frameworks, CDNs, WAF presence)
- Missing security headers (CSP, X-Frame-Options, HSTS)
- Exposed API endpoints, GraphQL introspection, `.env` files
- Email addresses and internal links harvested from crawl
- Threat intelligence from VirusTotal, Shodan, AbuseIPDB (if keys configured)

**Interpreting the Shadow Score:**
- **0–25 CLEAN** — minimal exposure, good security posture
- **26–50 ELEVATED** — some findings worth reviewing
- **51–75 HIGH** — significant issues, remediation recommended
- **76–100 CRITICAL** — urgent issues, active risk

---

### Scenario B — IP / Server Reconnaissance

**Goal:** Enumerate open services and threat history for an IP address.

**Recommended settings:**
- Target: `192.168.1.100` (or public IP)
- Profile: **Standard Recon** or **Deep Dive** (for full port scan)
- Modules: Port Scanner ✓, DNS Recon ✓, Intel APIs ✓
- Port Profile: **Extended (1000 ports)** or **Full (65535)** for thorough coverage

**What PhantomSignal will find:**
- All open TCP ports with service/version from nmap (`-sV`) and banner grabbing — falls back to pure-Python async prober when nmap unavailable
- **OS fingerprint** — detected automatically via nmap `-O` and shown in the port panel footer (e.g. "Linux 5.15 [95%]")
- Reverse DNS and PTR records
- ASN, ISP, geolocation data (IPInfo — no key required)
- CVE matches via Shodan (if API key set)
- AbuseIPDB confidence score and report history
- VirusTotal passive DNS, malware history
- GreyNoise classification (scanner, benign, unknown)

**Tip:** nmap is used automatically when present. On Kali/Parrot it's pre-installed. On macOS install via `brew install nmap`; on Windows via the nmap.org installer. Without nmap the async TCP scanner still runs — you just won't get version strings or OS detection.

---

### Scenario C — Domain Intelligence

**Goal:** Map the full attack surface of a domain.

**Recommended settings:**
- Target: `example.com`
- Profile: **Standard Recon** or **Deep Dive**
- Modules: DNS Recon ✓, Tech Detector ✓, Intel APIs ✓, Web Crawler ✓
- Crawl depth: 3

**What PhantomSignal will find:**
- All DNS records (A, AAAA, MX, NS, TXT, SOA, CAA)
- Zone transfer vulnerabilities
- Subdomain enumeration via brute-force wordlist + certificate transparency (crt.sh)
- SPF, DMARC, DKIM configuration issues (email spoofing risk)
- WHOIS registrant data and expiry
- Co-hosted domains and shared infrastructure
- SecurityTrails historical DNS (if API key set)

**Tip:** For maximum subdomain coverage configure both a **SecurityTrails** key and enable certificate transparency — these two sources together find far more subdomains than brute-force alone.

---

### Scenario D — People Intelligence (Shadow Profiler)

**Goal:** Aggregate publicly available information about a person, email address, or online identity.

**Navigate to:** Shadow Grid → **SHADOW PROFILER**

**Input types supported:**
- Full name + optional location/employer
- Email address
- Username / handle
- Phone number

**What PhantomSignal aggregates:**
- Public social media profiles (GitHub, Twitter/X, LinkedIn via Clearbit)
- Breach exposure via HaveIBeenPwned (requires HIBP API key)
- People-search aggregator data (Pipl, FullContact, Spokeo, WhitePages — keys required)
- Email validity and domain reputation
- Associated accounts and aliases

**Privacy note:** The Shadow Profiler only queries publicly available data sources and licensed APIs. Configure only the APIs you have a legitimate subscription to. GDPR and CCPA restrictions apply — see [Legal & Ethics](../README.md#️-legal--ethics).

---

### Scenario E — Bug Bounty Recon

**Goal:** Efficiently enumerate in-scope assets for a bug bounty programme.

**Workflow:**

1. **Quick Probe** each root domain to identify live assets
2. For live targets, run **Standard Recon** with all modules enabled
3. Focus review on:
   - API Hunter results (`/api/`, `/graphql`, admin panels)
   - High/Critical severity findings
   - Exposed `.git`, `.env`, `backup` paths in web crawl
   - Subdomains pointing to unclaimed cloud services (subdomain takeover candidates)
4. Export results as **JSON** for integration with your notes / Burp Suite

**Useful API keys for bug bounty:**
- **Shodan** — CVE and banner data
- **SecurityTrails** — historical DNS for subdomain discovery
- **URLScan.io** — passive screenshot and DOM analysis
- **VirusTotal** — passive DNS and URL history

**Tip:** Use the **Covert** profile if the programme's scope rules require low-noise recon. Enable **Respect robots.txt** to avoid accidental out-of-scope crawling.

---

### Scenario F — Covert Recon (Low-and-Slow)

**Goal:** Perform recon with the lowest possible noise and detection footprint.

**Settings:**
- Profile: **Covert**
- Enable **Evasive (low & slow)** toggle in Advanced Config
- Respect robots.txt: **on**
- Crawl depth: **1** (surface only)

**What the Covert profile and Evasive mode do:**
- Add random jitter (2–8 seconds) between requests
- Rotate User-Agent strings to mimic different browsers
- Reduce concurrent connections to 1
- Skip aggressive techniques (zone transfers, brute-force subdomain)
- Optionally route traffic via Tor (Docker `covert` profile only)

**Docker + Tor:**
```bash
docker-compose --profile covert up -d
```
This spins up a Tor sidecar and routes all PhantomSignal traffic through it automatically.

**Tip:** Covert scanning significantly increases scan duration. Plan for 30–90 minutes on a moderately sized target.

---

## 5. Configuring API Keys

Navigate to **Ghost Keys** (⚙ in the nav bar).

### Priority keys (highest value, free tiers available)

| API | Free Tier | What It Adds |
|-----|-----------|--------------|
| **Shodan** | 100 queries/month | CVEs, banners, open ports from passive scans |
| **VirusTotal** | 500 lookups/day | Malware, passive DNS, URL reputation |
| **AbuseIPDB** | 1,000/day | IP abuse reports, confidence scores |
| **IPInfo** | 50,000/month | ASN, geolocation, ISP |
| **SecurityTrails** | 50/month | Subdomain history, historical DNS |
| **HaveIBeenPwned** | Paid (cheap) | Breach exposure for emails |
| **Hunter.io** | 25/month | Email discovery from domains |

### Setting keys via environment variables

Keys entered in the Ghost Keys UI are stored in the local SQLite database. For production or Docker deployments, prefer environment variables:

```bash
export SHODAN_API_KEY="your-key"
export VIRUSTOTAL_API_KEY="your-key"
export ABUSEIPDB_API_KEY="your-key"
export IPINFO_TOKEN="your-key"
export HUNTER_API_KEY="your-key"
export HIBP_API_KEY="your-key"
export SECURITYTRAILS_API_KEY="your-key"
```

Or add them to a `.env` file in the project root (Docker Compose picks this up automatically).

---

## 6. Reading Results

### Results page layout

After a scan completes, the results page shows:

- **Meta strip** — target, profile, duration, result count, Shadow Score, threat level
- **Tabs** — ALL · per-module tabs · ANOMALIES (auto-filtered)
- **Type-aware result cards** — each result type renders its key data as structured output rather than raw JSON: open ports show port/service/version/banner/risk in one row; DNS records display as a labelled table; email security shows SPF/DMARC/spoofable status; security posture shows grade A–F; IP geolocation shows city/ASN/TOR/VPN flags; and so on. Click any card to expand it.
- **Export panel** — download in any supported format

### Severity levels

| Level | Colour | Meaning |
|-------|--------|---------|
| **CRITICAL** | Red | Immediate risk — active exploit, exposed credentials |
| **HIGH** | Orange/Red | Significant vulnerability requiring prompt remediation |
| **MEDIUM** | Yellow | Notable finding, assess and plan remediation |
| **LOW** | Green | Informational, minor exposure |
| **INFO** | Blue/Dim | Context data, no direct risk |

### Shadow Score breakdown

The Shadow Score (0–100) is a weighted composite:
- Open high-risk ports (admin panels, databases) — high weight
- Critical/High severity findings — high weight
- Missing security headers — medium weight
- Exposed subdomains and services — medium weight
- Breach exposure and threat intel flags — variable weight

---

## 7. Exporting Intel

From any scan results page, click **↓ EXPORT INTEL** and choose a format:

| Format | Best For |
|--------|----------|
| **JSON** | Programmatic processing, importing to other tools |
| **HTML** | Shareable self-contained styled report |
| **PDF** | Formal client deliverable |
| **CSV** | Spreadsheet analysis in Excel / Google Sheets |
| **XLSX** | Excel workbook with multiple sheets per module |
| **STIX 2.1** | Threat intelligence sharing (SOC / SIEM integration) |
| **XML** | Legacy system import |
| **Markdown** | Documentation, GitHub issues, Notion |

### Encrypting exports

All formats support **AES-256-GCM encryption**. Check the **Encrypt** checkbox before exporting and set a passphrase. The encrypted file includes a nonce and authentication tag — decryption requires PhantomSignal or a compatible AES-256-GCM implementation.

---

## 8. CLI Usage

```bash
# Activate virtual environment first
source .venv/bin/activate

# Quick scan — renders DNS, port, tech, API, intel panels in terminal
phantomsignal scan example.com --profile quick

# IP recon — nmap version+OS detection, 99-port default, GeoIP
phantomsignal scan 192.168.1.1 --type ip_recon

# Full spectrum with HTML report
phantomsignal scan example.com --profile standard --format html --output ./reports

# Deep dive — all ports, all modules
phantomsignal scan 192.168.1.1 --type ip_recon --profile deep --format json

# People intelligence
phantomsignal profile --email target@example.com --first-name John --last-name Doe

# List all available APIs and their status
phantomsignal apis

# Check version
phantomsignal --version
```

**CLI output (v1.3.0+):** After the scan completes, results are rendered as named Rich panels — one per active module — rather than a flat table. Each panel extracts the key fields from result data: the port panel shows PORT/SERVICE/PROTO/VERSION/BANNER/RISK with dangerous ports highlighted; the DNS panel shows resolved IPs, MX/NS/TXT records, subdomains, and SPF/DMARC status; the tech panel shows detected stack, security header grade, and TLS info; anomalies appear in a separate red-bordered callout. The footer shows Shadow Score, Threat Level, and a hint to configure API keys for deeper coverage.

### Common flags

| Flag | Description |
|------|-------------|
| `--profile quick\|standard\|deep\|covert` | Scan profile |
| `--type web_recon\|ip_recon\|domain_recon\|full_spectrum` | Scan type (auto-detected if omitted) |
| `--format json\|html\|pdf\|csv\|stix` | Output format |
| `--output <path>` | Output directory (default: `./reports`) |
| `--modules dns,port,tech` | Comma-separated module list |
| `--no-browser` | Skip web browser launch on completion |

---

## 9. Troubleshooting

### Linux

**Port 5000 already in use**
```bash
fuser -k 5000/tcp
python run.py
```

**`pip install` fails with missing system libs (WeasyPrint / cryptography)**
```bash
sudo apt-get install -y \
  build-essential libssl-dev libffi-dev \
  libcairo2 libpango-1.0-0 libgdk-pixbuf2.0-0
pip install -e .
```

**SQLite database locked**
```bash
# Kill any stale PhantomSignal process
pkill -f "python run.py"
# If the DB is still locked:
fuser phantomsignal/data/phantomsignal.db
```

**SocketIO connection shows "CONNECTING..." permanently**

Check that your browser isn't blocking WebSocket connections. If running behind a reverse proxy (nginx), add:
```nginx
proxy_http_version 1.1;
proxy_set_header Upgrade $http_upgrade;
proxy_set_header Connection "upgrade";
```

**Permission denied on `/phantomsignal/data/`**
```bash
chmod 755 phantomsignal/data
```

---

### macOS

**`Python 3.10+` not found**
```bash
brew install python@3.11
# Then use python3.11 explicitly:
python3.11 -m venv .venv
```

**`cryptography` build fails on Apple Silicon (M1/M2/M3)**
```bash
brew install openssl rust
export LDFLAGS="-L$(brew --prefix openssl)/lib"
export CPPFLAGS="-I$(brew --prefix openssl)/include"
pip install cryptography
```

**WeasyPrint errors (PDF export)**
```bash
brew install cairo pango gdk-pixbuf libffi
pip install weasyprint
```

**Port 5000 blocked by AirPlay Receiver (macOS Monterey+)**

macOS Monterey and later reserves port 5000 for AirPlay. Either disable AirPlay Receiver in *System Settings → General → AirDrop & Handoff*, or run PhantomSignal on a different port:
```bash
PHANTOMSIGNAL_PORT=5001 python run.py
# Then open http://127.0.0.1:5001
```

**`ssl: CERTIFICATE_VERIFY_FAILED` errors during scans**
```bash
/Applications/Python\ 3.x/Install\ Certificates.command
# Or:
pip install certifi
```

---

### Windows

**Running PhantomSignal on Windows**

PhantomSignal is primarily tested on Linux and macOS. Windows support is provided via WSL2 (recommended) or native Python.

**Recommended: WSL2**
```powershell
# In PowerShell (run as Administrator)
wsl --install
# Then open WSL terminal and follow the Linux instructions above
```

**Native Python — virtual environment activation**
```cmd
python -m venv .venv
.venv\Scripts\activate.bat
pip install -e .
python run.py
```

**`Hack-Regular.ttf` not found (phantom PNG render)**

The phantom asset render script (`scripts/render_phantom.py`) requires the Hack font. On Windows:
1. Download Hack from https://sourcefoundry.org/hack/
2. Install the font system-wide
3. Update `FONT_PATH` in `scripts/render_phantom.py`:
```python
FONT_PATH = "C:/Windows/Fonts/Hack-Regular.ttf"
```

**`asyncio` errors on Windows (Python 3.10)**

Add to the top of `run.py` if you see `RuntimeError: Event loop is closed`:
```python
import asyncio
asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
```

**Scrapy not crawling on Windows**

Scrapy requires the `twisted` reactor. If crawls hang:
```bash
pip install twisted[windows_platform]
```

**Firewall blocking port 5000**

Allow inbound connections to port 5000 in Windows Defender Firewall, or use `localhost` only (default behaviour is already localhost-bound).

---

### Docker

**Container starts but web UI is unreachable**
```bash
# Check container is running
docker-compose ps

# Check logs for errors
docker-compose logs phantomsignal

# Confirm port binding
docker-compose port phantomsignal 5000
```

**API keys not persisting between container restarts**

Mount a volume for the data directory:
```yaml
# docker-compose.yml
volumes:
  - ./data:/app/phantomsignal/data
```

**Database migration errors on upgrade**
```bash
docker-compose down
docker volume rm phantomsignal_data
docker-compose up -d
```
> ⚠ This clears all scan history. Back up `phantomsignal/data/phantomsignal.db` first.

**Scans complete instantly with 0 results (DNS not resolving in container)**
```bash
# Test DNS inside container
docker-compose exec phantomsignal nslookup example.com

# If failing, add DNS servers to docker-compose.yml:
services:
  phantomsignal:
    dns:
      - 8.8.8.8
      - 1.1.1.1
```

**Out of memory during Deep Dive scans**

Increase Docker Desktop memory allocation (Settings → Resources → Memory) to at least 2 GB. For very large targets, 4 GB recommended.

**Tor (Covert) container not connecting**
```bash
docker-compose --profile covert logs tor
# Common fix — wait 30s for Tor circuit establishment, then retry the scan
```

**Rebuilding after code changes**
```bash
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

---

## Getting Help

- **GitHub Issues:** https://github.com/getphantomsignal/phantomsignal/issues
- **About page:** Click **ABOUT** in the footer for version info and capability overview
- **Logs:** Check `/tmp/phantomsignal.log` (manual) or `docker-compose logs` (Docker) for detailed error output
