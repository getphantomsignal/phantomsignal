# PhantomSignal

```
    ____  __  _____    _   ____________  __  ___
   / __ \/ / / /   |  / | / /_  __/ __ \/  |/  /
  / /_/ / /_/ / /| | /  |/ / / / / / / / /|_/ /
 / ____/ __  / ___ |/ /|  / / / / /_/ / /  / /
/_/   /_/ /_/_/  |_/_/ |_/ /_/  \____/_/  /_/

   _____ ___________   _____    __
  / ___//  _/ ____/ | / /   |  / /
  \__ \ / // / __/  |/ / /| | / /
 ___/ // // /_/ / /|  / ___ |/ /___
/____/___/\____/_/ |_/_/  |_/_____/

         >> OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK <<
                 "Map the surface. Own the signal."
```

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-00ff41?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-00f3ff?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Docker-b026ff?style=flat-square)]()
[![GitHub Stars](https://img.shields.io/github/stars/getphantomsignal/phantomsignal?style=flat-square&color=00ff41)](https://github.com/getphantomsignal/phantomsignal/stargazers)
[![Open Issues](https://img.shields.io/github/issues/getphantomsignal/phantomsignal?style=flat-square&color=b026ff)](https://github.com/getphantomsignal/phantomsignal/issues)
[![CI](https://img.shields.io/github/actions/workflow/status/getphantomsignal/phantomsignal/ci.yml?branch=main&style=flat-square&label=CI&color=00ff41)](https://github.com/getphantomsignal/phantomsignal/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/phantomsignal?style=flat-square&color=b026ff&logo=pypi&logoColor=white)](https://pypi.org/project/phantomsignal/)
[![Project Site](https://img.shields.io/badge/site-phantomsignal.sh-00f3ff?style=flat-square&logo=github)](https://phantomsignal.sh)
[![Changelog](https://img.shields.io/badge/changelog-view-00ff41?style=flat-square)](CHANGELOG.md)
[![Sponsors](https://img.shields.io/github/sponsors/getphantomsignal?style=flat-square&color=b026ff&label=sponsors)](https://github.com/sponsors/getphantomsignal)


---

## ⚡ What's New in v1.4.3

### Quick probe full intel coverage
The intel orchestrator now correctly routes every target type to all relevant APIs. **Username targets** now trigger all social and people-intel sources (GitHub, Reddit, HackerNews, Keybase, Mastodon, Twitter, LinkedIn, Telegram, Discord, Steam, and more). **Email targets** now include threat-intel and breach APIs (AlienVaultOTX, HIBP, IntelX, Gravatar, FullContact). **Domain targets** now include email-discovery sources (Hunter.io). **IP targets** now include dark-web sources (Intelligence X). Previously all of these were silently skipped.

### 16 new intelligence API integrations
Twitch, Mastodon (4 federated instances), Keybase, Gravatar, HackerNews, Tumblr, Flickr, Spotify, Steam, VK, Telegram (public channels), Discord (user + server lookup), Facebook/Meta Graph, EmailRep, Intelligence X (dark web / paste / breach search), and Abstract API phone validation. Total: **46+ intel sources**.

### Ghost Key invalid-key detection
The Ghost Key Vault TEST button now distinguishes a **rejected key** (HTTP 401/403) from a working key with no results. Invalid keys surface an amber `⚠ INVALID` badge directly on the key row — no more false `✓ OK` on a dead credential.

### AlienVault OTX timeout fix
OTX section requests (`general`, `reputation`, `geo`, `malware`, `passive_dns`) now run **concurrently** with an 8-second per-section cap instead of sequentially. Eliminates the consistent 30s timeout caused by OTX's slow `reputation` endpoint on IP scans.

### WebSocket live feed improvements
- Server syncs current scan progress to browsers that connect **after** a run has started — no more stuck-at-0% progress bar on direct URL navigation
- Polling fallback keeps the progress bar accurate even when SocketIO events are missed
- 1-second engine start delay eliminates the race condition where events fire before the browser joins the scan room

---

## 🎬 Demo

### CLI — Ghost Run in action

![CLI scan demo](https://raw.githubusercontent.com/getphantomsignal/phantomsignal/main/docs/assets/demo.gif)

### Web UI — Shadow Grid (Dashboard)

![Dashboard](https://raw.githubusercontent.com/getphantomsignal/phantomsignal/main/docs/assets/screenshot_dashboard.svg)

### Web UI — Launch Ghost Run

![Launch Ghost Run](https://raw.githubusercontent.com/getphantomsignal/phantomsignal/main/docs/assets/screenshot_launch.svg)

### Web UI — Scan Results

![Scan results](https://raw.githubusercontent.com/getphantomsignal/phantomsignal/main/docs/assets/screenshot_results.svg)

### Web UI — Theme Options

PhantomSignal ships with two built-in UI themes, selectable via the **☀/🌙 toggle** in the top navigation bar. Your preference is saved automatically and persists across sessions.

| Theme | Description |
|-------|-------------|
| **Dark** *(default)* | Cyberpunk aesthetic — deep charcoal background, neon green/cyan/purple accents, matrix rain canvas, glowing phantom logo |
| **Light** | "Phantom Dawn" — soft blue-grey background, muted accent palette, clean black ASCII logo, matrix rain disabled |

> **Asciinema recording:** Watch the full interactive demo on asciinema.org, or play it locally:
> ```bash
> pip install asciinema
> asciinema play https://raw.githubusercontent.com/getphantomsignal/phantomsignal/main/docs/assets/demo.cast
> ```

[![asciicast](https://asciinema.org/a/1190779.svg)](https://asciinema.org/a/1190779)

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

### 👤 Shadow Profiler (People Intelligence)
LexisNexis-style identity aggregation from public records:
- Cross-correlates data from multiple people-search APIs
- Discovers emails, phones, addresses, relatives, employers
- Breach data correlation via HIBP and other sources
- Social media profile linking
- **Shadow Score** — digital exposure quantification (0-100)
- Social graph building and timeline reconstruction

### 📦 Export Formats
| Format | Description |
|--------|-------------|
| **JSON** | Raw machine-readable data |
| **CSV** | Spreadsheet-compatible |
| **HTML** | Self-contained cyberpunk-styled report |
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
- **Shadow Score** — composite risk/exposure scoring
- **Scheduled Phantoms** — recurring automated ghost runs
- **API health monitor** — dashboard showing configured APIs and rate limits
- **Light/Dark theme** — toggle between cyberpunk Dark mode and "Phantom Dawn" Light mode via the ☀/🌙 button; preference persisted in localStorage
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
# Quick probe
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
    ├── templates/      — Cyberpunk Jinja2 templates
    └── static/         — CSS (cyberpunk), JS (matrix, terminal, app)
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

## 💜 Sponsors

PhantomSignal is free, open-source, and built on personal time. If it's useful to you, consider sponsoring to help cover infrastructure costs, domain renewals, trademark filing, and ongoing development.

**[→ Sponsor PhantomSignal on GitHub](https://github.com/sponsors/getphantomsignal)**

| Tier | $/mo | What it covers |
|---|---|---|
| Ghost Operative | $5 | Domain renewals & infrastructure |
| Shadow Agent | $15 | API integrations & dependency updates |
| Signal Sponsor | $50 | Trademark filing, new modules — listed in README |
| Grid Patron | $200 | Development sprints, roadmap input — prominent listing |

> Signal Sponsors ($50+) and Grid Patrons ($200+) are listed below.

<!-- SPONSORS -->
<!-- This section is updated when sponsors join -->
<!-- END SPONSORS -->

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

[![osint](https://img.shields.io/badge/osint-00ff41?style=flat-square)](https://github.com/topics/osint)
[![security](https://img.shields.io/badge/security-00f3ff?style=flat-square)](https://github.com/topics/security)
[![python](https://img.shields.io/badge/python-00f3ff?style=flat-square)](https://github.com/topics/python)
[![hacking](https://img.shields.io/badge/hacking-00ff41?style=flat-square)](https://github.com/topics/hacking)
[![cybersecurity](https://img.shields.io/badge/cybersecurity-b026ff?style=flat-square)](https://github.com/topics/cybersecurity)
[![reconnaissance](https://img.shields.io/badge/reconnaissance-00ff41?style=flat-square)](https://github.com/topics/reconnaissance)
[![recon](https://img.shields.io/badge/recon-00f3ff?style=flat-square)](https://github.com/topics/recon)
[![penetration-testing](https://img.shields.io/badge/penetration--testing-b026ff?style=flat-square)](https://github.com/topics/penetration-testing)
[![ethical-hacking](https://img.shields.io/badge/ethical--hacking-00ff41?style=flat-square)](https://github.com/topics/ethical-hacking)
[![bug-bounty](https://img.shields.io/badge/bug--bounty-00f3ff?style=flat-square)](https://github.com/topics/bug-bounty)
[![information-gathering](https://img.shields.io/badge/information--gathering-b026ff?style=flat-square)](https://github.com/topics/information-gathering)
[![threat-intelligence](https://img.shields.io/badge/threat--intelligence-00ff41?style=flat-square)](https://github.com/topics/threat-intelligence)
[![security-tools](https://img.shields.io/badge/security--tools-00f3ff?style=flat-square)](https://github.com/topics/security-tools)
[![network-scanner](https://img.shields.io/badge/network--scanner-b026ff?style=flat-square)](https://github.com/topics/network-scanner)
[![dns-recon](https://img.shields.io/badge/dns--recon-00ff41?style=flat-square)](https://github.com/topics/dns-recon)
[![infosec](https://img.shields.io/badge/infosec-00f3ff?style=flat-square)](https://github.com/topics/infosec)
[![flask](https://img.shields.io/badge/flask-b026ff?style=flat-square)](https://github.com/topics/flask)
[![security-research](https://img.shields.io/badge/security--research-00ff41?style=flat-square)](https://github.com/topics/security-research)
[![footprinting](https://img.shields.io/badge/footprinting-00f3ff?style=flat-square)](https://github.com/topics/footprinting)
[![automation](https://img.shields.io/badge/automation-b026ff?style=flat-square)](https://github.com/topics/automation)

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
