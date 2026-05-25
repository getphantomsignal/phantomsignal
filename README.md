# 🦉 NightOwl // PHANTOM SIGNAL

```
 ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗ ██╗    ██╗██╗
 ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔═══██╗██║    ██║██║
 ██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║   ██║██║ █╗ ██║██║
 ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║   ██║██║███╗██║██║
 ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╔╝╚███╔███╔╝███████╗
 ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝
         >> OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK <<
                 "See everything. Leave no trace."
```

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-00ff41?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/license-MIT-00f3ff?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Docker-b026ff?style=flat-square)]()


---

## ⚡ What is NightOwl?

NightOwl is a **community-powered, open-source OSINT intelligence framework** built for security researchers, penetration testers, investigators, and enthusiasts. It combines web scraping, network reconnaissance, people intelligence aggregation, and threat analysis into a single cohesive platform.

> **LEGAL DISCLAIMER:** NightOwl is for **authorized security research, OSINT investigations, and educational purposes only**. Only scan targets you have explicit permission to test. You are solely responsible for compliance with all applicable laws. The developers assume NO liability for misuse.

---

## 🔥 Features

### 🕷 Web Reconnaissance
- **Scrapy-powered** deep web crawler with JavaScript rendering support
- **Technology detection** — fingerprints 50+ technologies (CMS, frameworks, CDNs, WAFs)
- **API endpoint hunter** — discovers REST APIs, GraphQL, Swagger docs, admin panels, `.env` leaks
- **Security header analysis** with graded posture scoring
- **Email, phone, link, and comment harvesting**

### 🌐 Network Intelligence
- **Async port scanner** — 65,535 ports, banner grabbing, service detection
- **DNS recon** — A/AAAA/MX/NS/TXT/SOA/CAA, zone transfer attempts, subdomain brute-force
- **Certificate transparency** via crt.sh — uncover subdomains via SSL history
- **SPF/DMARC analysis** — identify email spoofing vulnerabilities
- **Reverse DNS** and co-hosted domain discovery

### 🔬 Intelligence APIs (30+ Integrations)

| Category | APIs |
|----------|------|
| **Network Scanning** | Shodan, Censys, ZoomEye, BinaryEdge |
| **Threat Intelligence** | VirusTotal, AbuseIPDB, GreyNoise, AlienVault OTX |
| **Email** | Hunter.io, HaveIBeenPwned, HaveIBeenPwned |
| **Domain/Web** | SecurityTrails, URLScan.io, WhoisXML, Local WHOIS |
| **Geolocation** | IPInfo.io |
| **People Search** | Pipl, FullContact, WhitePages, Spokeo, Clearbit |
| **Social** | GitHub, Twitter/X |
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
- **Full REST API** — integrate NightOwl into your own toolchain
- **CLI interface** — `nightowl scan`, `nightowl profile`, `nightowl export`
- **Docker** — single-command deployment

---

## 🚀 Quick Start

### Option 1: Docker (Recommended)
```bash
git clone https://github.com/nightowl-osint/nightowl
cd nightowl
docker-compose up -d
# Open http://localhost:5000
```

### Option 2: Manual Installation
```bash
# Python 3.10+ required
git clone https://github.com/nightowl-osint/nightowl
cd nightowl
pip install -e .
nightowl init
nightowl web --open-browser
```

### Option 3: CLI Scan
```bash
# Quick probe
nightowl scan example.com --profile quick

# Full spectrum with export
nightowl scan 192.168.1.1 --type ip_recon --format html --output ./reports

# People intelligence
nightowl profile --email target@company.com --first-name John --last-name Doe
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
# See config/nightowl.yaml for full list
```

### Config File
Copy `config/nightowl.yaml` to `~/.nightowl/config.yaml` and customize.

---

## 🔌 Adding Custom APIs

NightOwl uses a plugin architecture. Adding a new intelligence source takes ~20 lines:

```python
# nightowl/intel/apis/my_api.py
from nightowl.intel.apis.base import BaseIntelAPI, register_api, APICategory, APITier

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

Then import it in `nightowl/intel/orchestrator.py` and it auto-registers.

---

## 🏗 Architecture

```
nightowl/
├── core/               — Engine, config, database, models
├── scrapers/           — Scrapy crawler, tech detector, port scanner, API hunter, DNS recon
├── intel/
│   ├── apis/           — 30+ API integrations (plugin architecture)
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

NightOwl thrives on community contributions. Ways to help:

1. **Add API integrations** — Follow the plugin pattern above
2. **Improve detection signatures** — Expand `tech_detector.py`
3. **Bug reports** — [GitHub Issues](https://github.com/nightowl-osint/nightowl/issues)
4. **Documentation** — Improve the wiki
5. **Translations** — Internationalize the UI

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## ⚠️ Legal & Ethics

NightOwl is a dual-use tool. Operators are responsible for:
- Obtaining explicit authorization before scanning any system
- Complying with applicable laws (CFAA, GDPR, CCPA, ECPA, local laws)
- Respecting privacy and data protection regulations
- Not using this tool for harassment, stalking, or unauthorized surveillance

**The developers provide this software as-is with no warranty. Misuse is your responsibility.**

---

## 📜 License

MIT License — see [LICENSE](LICENSE)

---

*Built with ☕ and questionable amounts of caffeine by the NightOwl community.*
*"The night sees all. The owl forgets nothing."*    
