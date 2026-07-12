# PhantomSignal

> **Open-source OSINT intelligence framework** — _"Map the surface. Own the signal."_

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-4d9fd6?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-7fb8dd?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Docker-c9a24a?style=flat-square)]()
[![GitHub Stars](https://img.shields.io/github/stars/getphantomsignal/phantomsignal?style=flat-square&color=4d9fd6)](https://github.com/getphantomsignal/phantomsignal/stargazers)
[![Open Issues](https://img.shields.io/github/issues/getphantomsignal/phantomsignal?style=flat-square&color=c9a24a)](https://github.com/getphantomsignal/phantomsignal/issues)
[![CI](https://img.shields.io/github/actions/workflow/status/getphantomsignal/phantomsignal/ci.yml?branch=main&style=flat-square&label=CI&color=4d9fd6)](https://github.com/getphantomsignal/phantomsignal/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/phantomsignal?style=flat-square&color=c9a24a&logo=pypi&logoColor=white)](https://pypi.org/project/phantomsignal/)
[![Project Site](https://img.shields.io/badge/site-phantomsignal.sh-7fb8dd?style=flat-square&logo=github)](https://phantomsignal.sh)
[![Changelog](https://img.shields.io/badge/changelog-view-4d9fd6?style=flat-square)](CHANGELOG.md)


---

## ⚡ What's New in v1.24.0

### Streamlined to two themes
The web console now ships **two** carefully tuned themes built on semantic role tokens — **Dark** (a deep-slate federal console, the default) and **Light** (clean and print-friendly). Switch from the ☀ / ☾ segmented control in the nav; your choice persists in the browser and is applied before first paint, so there's no flash on reload. Every token in both themes is validated to **WCAG AA** contrast.

### Plain-language interface
The web UI was rewritten from codenames to clear, function-first labels — **Dashboard, New Scan, Scans, Profiler, Integrations** — so a first-time user can tell what everything does. Findings, Risk Score, Data Sources, and consistent severity language throughout.

### Roboto type + signal mark
Roboto for UI text (tables, terminal, and code stay monospace for alignment), a font-based `∿` signal glyph replacing the old ASCII logo, and a PS-monogram favicon.

### Clickable dashboard + one-click re-scan
Dashboard stat cards are now links into the matching view, and any completed scan can be **re-run** against the same target with its original profile, modules, and options — from the results page or any Scans-list row.

### Honest risk gradient
The Risk Score meter now runs a true green → amber → red ramp, so a low score reads green (safe) at a glance in every theme.

---

## 🎬 A Scan in Action

A single command runs the full pipeline — DNS and WHOIS resolution, port and
service scanning, technology fingerprinting, threat-intelligence correlation
across 45+ sources, and a web-surface crawl — then rolls every finding into a
single Risk Score and writes a shareable HTML report.

```text
$ phantomsignal scan example.com --profile standard --format html

◈  Target   : example.com  (domain)
◈  Profile  : standard     (~2–5 min)
◈  Modules  : dns_recon port_scan tech_detect api_hunt web_crawl intel

[1/6] DNS & WHOIS ......... 42 records · 7 subdomains
[2/6] Port scan .......... 6 open · 22 80 443 8080 …
[3/6] Tech fingerprint ... nginx · Cloudflare · React · WordPress
[4/6] Threat intel ....... 31 sources queried · 0 malicious
[5/6] Web crawl .......... 128 URLs · 3 exposed endpoints
[6/6] Scoring ............ Risk Score 34 / 100 (MEDIUM)

✓  Report written → ./reports/example.com.html
```

Stages run concurrently where possible and degrade gracefully — a module
without a configured API key returns empty rather than failing the scan.

### Web UI — Theme Options

The web console ships with two built-in themes, selectable from the **segmented
switch** (☀ / ☾) in the top navigation bar. Your preference is saved
automatically and applied before first paint, so there's no flash on reload.
Every token in every theme is validated to WCAG AA contrast.

| Theme | Description |
|-------|-------------|
| **Dark** *(default)* | Deep-slate federal console — federal-blue hero, gold accents, restrained glow |
| **Light** | Clean daytime / print-friendly — white surfaces, federal-blue accents, flat (no glow) |

---

## ⚡ What is PhantomSignal?

PhantomSignal is a **community-powered, open-source OSINT intelligence framework** built for security researchers, penetration testers, investigators, and enthusiasts. It combines web scraping, network reconnaissance, people intelligence aggregation, and threat analysis into a single cohesive platform.

> **LEGAL DISCLAIMER:** PhantomSignal is for **authorized security research, OSINT investigations, and educational purposes only**. Only scan targets you have explicit permission to test. You are solely responsible for compliance with all applicable laws. The developers assume NO liability for misuse.

---

## 🔥 Features

### 🕷 Web Reconnaissance
- **Scrapy-powered** deep web crawler with JavaScript rendering support
- **Technology detection** — fingerprints 50+ technologies (CMS, frameworks, CDNs, WAFs)
- **API endpoint hunter** — discovers REST APIs, GraphQL, Swagger docs, admin panels, `.env` leaks
- **Security header analysis** with graded posture scoring
- **Email, phone, link, and comment harvesting**

### 🌐 Network Intelligence
- **nmap-powered port scanner** — full service-version detection and OS fingerprinting via nmap (`-sV -O`); pure-Python async TCP fallback when nmap unavailable — no config required
- **Expanded port coverage** — 99 common ports by default, 1,000+ port profile, or full 65,535; covers WinRM, Webmin, InfluxDB, Docker API, Kubernetes, and more
- **DNS recon** — A/AAAA/MX/NS/TXT/SOA/CAA, zone transfer attempts, subdomain brute-force
- **Certificate transparency** via crt.sh — uncover subdomains via SSL history
- **SPF/DMARC analysis** — identify email spoofing vulnerabilities
- **Reverse DNS** and co-hosted domain discovery

### 🔬 Intelligence APIs (46+ Integrations)

| Category | APIs |
|----------|------|
| **Network Scanning** | Shodan, Censys, ZoomEye, BinaryEdge |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX, Intelligence X |
| **Email & Breach** | Hunter.io, HaveIBeenPwned, EmailRep |
| **Domain/Web** | SecurityTrails, URLScan.io, WhoisXML, Local WHOIS |
| **Geolocation** | IPInfo.io |
| **Phone** | Abstract API phone validation |
| **People Search** | Pipl, FullContact, WhitePages, Spokeo, Clearbit |
| **Social** | GitHub, Twitter/X, Reddit, Mastodon, Keybase, Gravatar, HackerNews, Twitch, YouTube, Instagram, TikTok, LinkedIn, Tumblr, Flickr, Spotify, Steam, VK, Telegram, Discord, Facebook |
| **Custom** | Bring your own API via plugin architecture |

### 👤 Profiler (People Intelligence)
LexisNexis-style identity aggregation from public records:
- Cross-correlates data from multiple people-search APIs
- Discovers emails, phones, addresses, relatives, employers
- Breach data correlation via HIBP and other sources
- Social media profile linking
- **Risk Score** — digital exposure quantification (0-100)
- Social graph building and timeline reconstruction

### 📦 Export Formats
| Format | Description |
|--------|-------------|
| **JSON** | Raw machine-readable data |
| **CSV** | Spreadsheet-compatible |
| **HTML** | Self-contained styled report |
| **PDF** | Professional dossier via ReportLab |
| **XML** | Structured data |
| **XLSX** | Excel workbook |
| **STIX 2.1** | Threat intelligence sharing format |
| **Markdown** | Human-readable report |

All formats support **ZIP compression** and **AES-256-GCM encryption**.

### 🌑 Ghost Mode
- Low-and-slow scanning profiles to minimize detection
- Identity rotation via user-agent spoofing
- Tor proxy integration (Docker compose profile: `ghost`)
- Configurable request jitter and delays

### 🔔 Additional Features
- **Real-time live feed** — WebSocket-powered terminal during scans
- **Risk Score** — composite risk/exposure scoring
- **Scheduled Phantoms** — recurring automated scans
- **API health monitor** — dashboard showing configured APIs and rate limits
- **Light / Dark themes** — switch between the default Dark console and a clean Light mode from the ☀ / ☾ segmented control in the nav; preference persisted in localStorage and applied before first paint
- **Full REST API** — integrate PhantomSignal into your own toolchain
- **CLI interface** — `phantomsignal scan`, `phantomsignal profile`, `phantomsignal export`
- **Docker** — single-command deployment

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
git clone https://github.com/getphantomsignal/phantomsignal
cd phantomsignal
docker-compose up -d
# Open http://localhost:5000
```

### Option 2: Manual Installation
```bash
# Python 3.10+ required
git clone https://github.com/getphantomsignal/phantomsignal
cd phantomsignal
pip install -e .
phantomsignal init
phantomsignal web --open-browser
```

### Option 3: CLI Scan
```bash
# Quick scan
phantomsignal scan example.com --profile quick

# Full spectrum with export
phantomsignal scan 192.168.1.1 --type ip_recon --format html --output ./reports

# People intelligence
phantomsignal profile --email target@company.com --first-name John --last-name Doe
```

---

## ⚙️ Configuration

### Environment Variables (Recommended for API Keys)
```bash
export SHODAN_API_KEY="your-shodan-key"
export VIRUSTOTAL_API_KEY="your-vt-key"
export HUNTER_API_KEY="your-hunter-key"
export HIBP_API_KEY="your-hibp-key"
export GREYNOISE_API_KEY="your-greynoise-key"
export IPINFO_TOKEN="your-ipinfo-token"
export ABUSEIPDB_API_KEY="your-abuseipdb-key"
export ALIENVAULT_API_KEY="your-otx-key"
export GITHUB_TOKEN="your-github-token"
export SECURITYTRAILS_API_KEY="your-st-key"
# See config/phantomsignal.yaml for full list
```

### Config File
Copy `config/phantomsignal.yaml` to `~/.phantomsignal/config.yaml` and customize.

---

## 🔌 Adding Custom APIs

PhantomSignal uses a plugin architecture. Adding a new intelligence source takes ~20 lines:

```python
# phantomsignal/intel/apis/my_api.py
from phantomsignal.intel.apis.base import BaseIntelAPI, register_api, APICategory, APITier

@register_api
class MyAPI(BaseIntelAPI):
    NAME = "myapi"
    DESCRIPTION = "My custom intelligence source"
    REQUIRES_KEY = True
    TIER = APITier.FREE_LIMITED
    CATEGORIES = [APICategory.NETWORK]
    BASE_URL = "https://api.myservice.com/v1"
    SIGN_UP_URL = "https://myservice.com/signup"

    async def search(self, query: str, **kwargs):
        data = await self._get(
            f"{self.BASE_URL}/search",
            params={"q": query, "key": self._api_key}
        )
        return [self._wrap_result("my_result", data)]
```

Then import it in `phantomsignal/intel/orchestrator.py` and it auto-registers.

---

## 🏗 Architecture

```
phantomsignal/
├── core/               — Engine, config, database, models
├── scrapers/           — Scrapy crawler, tech detector, port scanner, API hunter, DNS recon
├── intel/
│   ├── apis/           — 46+ API integrations (plugin architecture)
│   └── people/         — People intelligence aggregation
├── exporters/          — JSON/CSV/PDF/HTML/XML/XLSX/STIX + crypto wrapper
└── web/
    ├── routes/         — Flask blueprints (dashboard, scans, intel, settings, export, REST API)
    ├── templates/      — Jinja2 templates
    └── static/         — CSS (role-token themes), JS (terminal, app)
```

---

## 🛡 REST API

```bash
# Create a scan
curl -X POST http://localhost:5000/api/v1/scans \
  -H "Content-Type: application/json" \
  -d '{"target": "example.com", "scan_type": "web_recon"}'

# Get results
curl http://localhost:5000/api/v1/scans/{scan_id}

# List all APIs
curl http://localhost:5000/api/v1/apis

# Health check
curl http://localhost:5000/api/v1/health
```

---

## 🤝 Contributing

PhantomSignal thrives on community contributions. Ways to help:

1. **Add API integrations** — Follow the plugin pattern above
2. **Improve detection signatures** — Expand `tech_detector.py`
3. **Bug reports** — [GitHub Issues](https://github.com/getphantomsignal/phantomsignal/issues)
4. **Documentation** — Improve the wiki
5. **Translations** — Internationalize the UI

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Please also review our [Code of Conduct](CODE_OF_CONDUCT.md) and [Security Policy](SECURITY.md).

---

## 📖 Documentation

- **[Usage Guide](docs/USAGE.md)** — full walkthroughs, usage scenarios, CLI reference, and per-platform troubleshooting (Linux / macOS / Windows / Docker)

---

## ⚠️ Legal & Ethics

PhantomSignal is a dual-use tool. Operators are responsible for:
- Obtaining explicit authorization before scanning any system
- Complying with applicable laws (CFAA, GDPR, CCPA, ECPA, local laws)
- Respecting privacy and data protection regulations
- Not using this tool for harassment, stalking, or unauthorized surveillance

**The developers provide this software as-is with no warranty. Misuse is your responsibility.**

---

## 🏷 Topics

[![osint](https://img.shields.io/badge/osint-4d9fd6?style=flat-square)](https://github.com/topics/osint)
[![security](https://img.shields.io/badge/security-7fb8dd?style=flat-square)](https://github.com/topics/security)
[![python](https://img.shields.io/badge/python-7fb8dd?style=flat-square)](https://github.com/topics/python)
[![hacking](https://img.shields.io/badge/hacking-4d9fd6?style=flat-square)](https://github.com/topics/hacking)
[![cybersecurity](https://img.shields.io/badge/cybersecurity-c9a24a?style=flat-square)](https://github.com/topics/cybersecurity)
[![reconnaissance](https://img.shields.io/badge/reconnaissance-4d9fd6?style=flat-square)](https://github.com/topics/reconnaissance)
[![recon](https://img.shields.io/badge/recon-7fb8dd?style=flat-square)](https://github.com/topics/recon)
[![penetration-testing](https://img.shields.io/badge/penetration--testing-c9a24a?style=flat-square)](https://github.com/topics/penetration-testing)
[![ethical-hacking](https://img.shields.io/badge/ethical--hacking-4d9fd6?style=flat-square)](https://github.com/topics/ethical-hacking)
[![bug-bounty](https://img.shields.io/badge/bug--bounty-7fb8dd?style=flat-square)](https://github.com/topics/bug-bounty)
[![information-gathering](https://img.shields.io/badge/information--gathering-c9a24a?style=flat-square)](https://github.com/topics/information-gathering)
[![threat-intelligence](https://img.shields.io/badge/threat--intelligence-4d9fd6?style=flat-square)](https://github.com/topics/threat-intelligence)
[![security-tools](https://img.shields.io/badge/security--tools-7fb8dd?style=flat-square)](https://github.com/topics/security-tools)
[![network-scanner](https://img.shields.io/badge/network--scanner-c9a24a?style=flat-square)](https://github.com/topics/network-scanner)
[![dns-recon](https://img.shields.io/badge/dns--recon-4d9fd6?style=flat-square)](https://github.com/topics/dns-recon)
[![infosec](https://img.shields.io/badge/infosec-7fb8dd?style=flat-square)](https://github.com/topics/infosec)
[![flask](https://img.shields.io/badge/flask-c9a24a?style=flat-square)](https://github.com/topics/flask)
[![security-research](https://img.shields.io/badge/security--research-4d9fd6?style=flat-square)](https://github.com/topics/security-research)
[![footprinting](https://img.shields.io/badge/footprinting-7fb8dd?style=flat-square)](https://github.com/topics/footprinting)
[![automation](https://img.shields.io/badge/automation-c9a24a?style=flat-square)](https://github.com/topics/automation)

---

## 🤝 Community

| Document | Description |
|----------|-------------|
| [Code of Conduct](CODE_OF_CONDUCT.md) | Community standards and expectations |
| [Contributing Guidelines](CONTRIBUTING.md) | How to contribute to PhantomSignal |
| [Security Policy](SECURITY.md) | Reporting vulnerabilities responsibly |
| [License](LICENSE) | MIT License terms |

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

*Built with questionable amounts of caffeine. "Map the surface. Own the signal."*
*Some ghosts leave no trace. This one left commits. — Claude*    
