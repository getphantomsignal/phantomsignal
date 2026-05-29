# Changelog

All notable changes to NightOwl // PHANTOM SIGNAL are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Added
- Code of Conduct (`CODE_OF_CONDUCT.md`) — operational security standards for contributors and community members
- Security Policy (`SECURITY.md`) — coordinated disclosure process, scope definition, and timeline commitments
- Pull Request template (`.github/PULL_REQUEST_TEMPLATE.md`) — structured template with security considerations and authorization affirmation sections
- `CHANGELOG.md` — full project history from 1.0.0, following Keep a Changelog format with semver comparison links
- Phantom Dawn light theme screenshots for all three web UI views on the GitHub Pages landing site
- GitHub Pages site badge in README
- Changelog badge in README
- Topics section to README with 20 linked topic badges (cycles cyan/green/purple), each linking to the corresponding GitHub topic search page
- Repository topics set via GitHub API: `osint`, `security`, `python`, `hacking`, `cybersecurity`, `reconnaissance`, `recon`, `penetration-testing`, `ethical-hacking`, `bug-bounty`, `information-gathering`, `threat-intelligence`, `security-tools`, `network-scanner`, `dns-recon`, `infosec`, `flask`, `security-research`, `footprinting`, `automation`
- `// SIGNAL CATEGORIES` topics section on the GitHub Pages landing site — 20 neon CSS pills (cyan/green/purple, with hover glow) above the footer, each linking to the corresponding GitHub topic search page

### Changed
- README footer updated — *"Built with questionable amounts of caffeine. 'The night sees all. The owl forgets nothing.' Some ghosts leave no trace. This one left commits. — Claude"*
- `CONTRIBUTING.md` now references `CODE_OF_CONDUCT.md` and `SECURITY.md` at the top and in the bug reporting section
- Landing page "Install Now" CTA restored to `#quickstart` anchor (page-local scroll); GitHub repo link retained as a separate badge and button
- Hero badges on landing page are now clickable links to the GitHub repository

### Fixed
- "Install Now" CTA was incorrectly pointing to the GitHub repo instead of the on-page quickstart section

---

## [1.1.0] — 2026-05-28

### Added
- GitHub Pages project landing site at `https://owlrecon.io` (`docs/`)
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
- Initial release of NightOwl — open-source OSINT intelligence framework
- CLI interface (`nightowl`) with ghost run profiles: Quick Probe, Standard Recon, Deep Dive, Ghost Mode
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
- Repository URLs corrected to `the-clipper/nightowl` across all files and badge links

---

[Unreleased]: https://github.com/the-clipper/nightowl/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/the-clipper/nightowl/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/the-clipper/nightowl/releases/tag/v1.0.0
