# Changelog

All notable changes to OwlScan // PHANTOM SIGNAL are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [1.2.1] — 2026-05-30

### Fixed
- PyPI project description updated with correct asciinema recording URL and PyPI badge

---

## [1.2.0] — 2026-05-30

### Changed
- **Project renamed from NightOwl to OwlScan** — all references updated across codebase, docs, config, and assets
- Domain migrated from `owlrecon.io` → `owlscan.sh`; DNS configured with GitHub Pages A records
- GitHub org renamed `nightowl-osint` → `owlscan`; repo renamed `nightowl` → `owlscan`
- Python package renamed `nightowl` → `owlscan`; CLI entry point `nightowl` → `owlscan` (`owl` alias preserved)
- Config directory `~/.nightowl/` → `~/.owlscan/`; config file `nightowl.yaml` → `owlscan.yaml`
- Database default `nightowl.db` → `owlscan.db`
- Environment variable prefix `NIGHTOWL_*` → `OWLSCAN_*`
- ASCII banner art regenerated for OWLSCAN in `__init__.py`, README, and all demo assets
- Owl PNG graphic updated — footer label changed from "NightOwl" to "OwlScan" in both dark and transparent variants
- Demo GIF and asciinema cast regenerated with OWLSCAN banner and `owlscan` CLI command
- SVG screenshots regenerated with updated OWLSCAN branding throughout
- GitHub Pages landing site fully rebranded — nav, hero title, footer, and og tags
- GitHub org profile README rebranded with new ASCII art, updated badges and links
- GitHub repo About description and homepage URL updated to `owlscan.sh`
- Contact email updated to `security@owlscan.sh` across all docs

### Added
- Code of Conduct (`CODE_OF_CONDUCT.md`) — operational security standards for contributors and community members
- Security Policy (`SECURITY.md`) — coordinated disclosure process, scope definition, and timeline commitments
- Pull Request template (`.github/PULL_REQUEST_TEMPLATE.md`) — structured template with security considerations and authorization affirmation sections
- `CHANGELOG.md` — full project history from 1.0.0, following Keep a Changelog format with semver comparison links
- Phantom Dawn light theme screenshots for all three web UI views on the GitHub Pages landing site
- GitHub Pages site badge in README
- Changelog badge in README
- Topics section to README with 20 linked topic badges, each linking to the corresponding GitHub topic search page
- `// SIGNAL CATEGORIES` topics section on the GitHub Pages landing site

### Fixed
- "Install Now" CTA was incorrectly pointing to the GitHub repo instead of the on-page quickstart section

---

## [1.1.0] — 2026-05-28

### Added
- GitHub Pages project landing site at `https://owlscan.sh` (`docs/`)
  - Hero section with install block and copy button
  - Features grid, capabilities breakdown, quickstart tabs, and intelligence grid
  - Asciinema demo embed and SVG web UI screenshots
  - CTA section and project footer
- Phantom Dawn light mode theme — soft blue-grey palette, muted accent colours, matrix rain disabled, ASCII owl logo variant; toggleable via the `☀/🌙` button in the navigation bar; preference persists across sessions via `localStorage`
- Owl ASCII art render script for generating the light-theme logo asset
- User documentation (`docs/USAGE.md`) — comprehensive guide covering installation, CLI usage, web UI, ghost run profiles, module reference, export formats, and API key setup

### Changed
- Web UI navigation updated to link DOCS to `docs/USAGE.md` on GitHub
- README demo section updated with light/dark theme toggle documentation

### Fixed
- All DOCS links across the web interface and landing site now point to `docs/USAGE.md` on GitHub

---

## [1.0.0] — 2026-05-25

### Added
- Initial release of OwlScan — open-source OSINT intelligence framework
- CLI interface (`owlscan`) with ghost run profiles: Quick Probe, Standard Recon, Deep Dive, Ghost Mode
- Web interface (Flask + SocketIO) with Shadow Grid dashboard, live feed, scan launch, and results views
- Plugin/module API system with `@register_api` decorator for auto-registration
- Intelligence modules: DNS Recon, Port Scanner, Tech Detector, Web Crawler, API Hunter, People Intel, Intel APIs (Shodan, VirusTotal, AbuseIPDB, HaveIBeenPwned, Censys)
- Export pipeline: JSON, CSV, HTML, PDF, XLSX, STIX 2.1, XML, Markdown; all formats support ZIP compression and AES-256-GCM encryption
- Shadow Score — aggregate risk scoring system per scan
- GitHub Actions CI workflow (lint, test, build checks on push and PR)
- `CONTRIBUTING.md` with dev setup, plugin authoring guide, and PR guidelines
- CI status badge in README
- README demo section: animated CLI demo (GIF + asciinema cast), SVG web UI screenshots

### Fixed
- Repository URLs corrected to `owlscan/owlscan` across all files and badge links

---

[Unreleased]: https://github.com/owlscan/owlscan/compare/v1.2.1...HEAD
[1.2.1]: https://github.com/owlscan/owlscan/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/owlscan/owlscan/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/owlscan/owlscan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/owlscan/owlscan/releases/tag/v1.0.0
