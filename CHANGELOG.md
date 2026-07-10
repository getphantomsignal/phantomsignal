# Changelog

All notable changes to PhantomSignal // PHANTOM SIGNAL are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).  
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

---

## [1.10.0] — 2026-07-10

Classic DNS enumeration — the second Phase 3 "revive the footprinting canon"
release. `dns_recon` already pulled records, attempted zone transfer, and
brute-forced subdomains; this adds three techniques that surface names and
misconfigurations those passes miss, all authorised-active.

### Added
- **DNSSEC NSEC zone-walking** (`_nsec_walk`) — NSEC-signed zones leak every
  name via the NSEC `next` chain even when AXFR is refused. Sends non-recursive
  DNSSEC queries against an authoritative NS and follows the chain to its
  wrap-to-apex. Detects **NSEC3** (hashed) and reports it rather than pretending
  to walk it. Emits `nsec_zone_walk` (anomaly) and re-emits each in-zone name as
  a `subdomain` finding so it feeds the pivot + takeover engines.
- **PTR netblock sweep** (`_ptr_sweep`) — reverse-resolves the entire /24 around
  the target's A record (concurrency-bounded), surfacing co-hosted infrastructure.
  Emits `ptr_sweep_summary`; co-hosted names within the registered domain are
  re-emitted as `subdomain` findings for the pivot.
- **DNS cache snooping** (`_cache_snoop`) — non-recursive (RD=0) probes of the
  domain's nameservers for a set of common third-party domains. A cached answer
  means the server is cache-snoopable, revealing what its users recently
  resolved. Emits `dns_cache_snoop` (anomaly, open-resolver/misconfig tags).
- CLI `◈ DNS INTELLIGENCE` panel lines for NSEC walk, PTR sweep, and cache snoop.

### Correctness & validation
- Live NSEC/cache-snoop queries can't run in the sandbox (outbound UDP/53 is
  blocked), so the error-prone logic is unit-tested against crafted records: the
  pure walk driver `nsec_walk_names` (wrap-to-apex, loop, dead-end, and
  out-of-zone termination), NSEC/NSEC3 record parsing, and `/24` host expansion.
  The walk driver is bounded (`max_steps`) and network-free by construction.
- 6 new tests (`tests/test_dns_enum.py`); 64 tests pass.

---

## [1.9.0] — 2026-07-08

Classic enumeration release — the first of the Phase 3 "revive the footprinting
canon" modules. PhantomSignal already flagged ports 25/139/445/161 as dangerous
but never enumerated them; this adds correct, active enumeration for the two we
can implement from scratch with confidence.

### Added
- **Service enumeration** (`scrapers/service_enum.py`, `service_enum` module):
  - **SMTP (port 25)** — `VRFY`/`EXPN` username enumeration with an automatic
    `RCPT TO` fallback when `VRFY` is disabled, plus an **open-relay** check
    (a foreign `MAIL FROM` + foreign `RCPT TO` both accepted). For a domain
    target the MX host is resolved and probed. Emits `smtp_users` (valid
    mailboxes, flagged as anomalies) and `smtp_open_relay`.
  - **SNMP (port 161/udp)** — community-string enumeration via a hand-built
    SNMPv1 `GetRequest` for `sysDescr.0`; a valid community leaks the device
    description. Tries a small default/common community list and stops at the
    first hit. Emits `snmp_community` (with a `default-community` tag for
    `public`/`private`).
  - Wired into the engine pipeline, the CLI `--modules service_enum` with a
    dedicated results panel, and the web scan form (module card + result
    rendering for all three finding types).

### Correctness & validation
- The SNMP `GetRequest` encoder is validated **byte-for-byte** against the
  canonical `sysDescr.0` / community `public` reference packet, and the response
  parser round-trips a `GetResponse` and rejects `error-status`/non-SNMP input.
- The SMTP conversation (banner → `EHLO` → `VRFY`/`RCPT` → relay probe → `QUIT`)
  is verified end-to-end against an in-memory server: `VRFY` enumeration isolates
  valid users and open-relay detection fires correctly.
- Response classification and packet encode/parse are pure functions; **7 unit
  tests** added (52 → **58 total**).

### Deferred (deliberately)
- **NetBIOS/SMB null-session enumeration** (139/445) is *not* included. A correct
  implementation needs a real SMB stack (impacket); a hand-rolled one would be the
  kind of silently-wrong protocol code this project refuses to ship (see the JARM
  notes in v1.8.0). It is a tracked follow-up.

### Operational
- `service_enum` performs **active** enumeration (SMTP `VRFY`/`RCPT` probes, SNMP
  community guesses). Run it only against systems you are authorised to test.

---

## [1.8.0] — 2026-07-08

JARM release. Adds a validated, from-scratch **active TLS-stack fingerprint** to
the `infra_pivot` module, replacing the JARM that was deliberately deferred in
v1.7.0 rather than shipped incorrect. This entry is intentionally detailed: JARM
is an algorithm that is easy to get *almost* right and impossible to debug by eye,
so the failure modes are documented here as much as the feature.

### Added
- **JARM active TLS fingerprinting** (`scrapers/jarm.py`). Sends ten deliberately
  varied TLS Client Hellos and fuzzy-hashes the server's responses into the
  standard 62-character JARM. Two servers with the same TLS stack + configuration
  produce the same fingerprint, making it a high-signal infrastructure pivot.
  - Integrated into the `infra_pivot` module: emits a `jarm_fingerprint` result
    and pivots siblings via Shodan `ssl.jarm:<hash>`. Surfaced in the CLI
    `infra_pivot` panel and the web results view.
  - The ten-probe matrix varies TLS version (1.1/1.2/1.3), cipher-list ordering
    (forward / reverse / top-half / bottom-half / middle-out), GREASE injection,
    rare-ALPN sets, and extension ordering — the server's *disagreements* across
    these are the fingerprint.
  - Pure packet-construction and hashing functions are split from the socket
    driver; **7 unit tests** cover cipher reordering, hash encoding, Client Hello
    framing, and Server Hello parser guards. Total suite: **51 tests**.
- **Technical documentation** under `docs/jarm/` — a from-the-inside-out
  walkthrough written because this was built from scratch:
  - `README.md` — what JARM is and why it uses deliberately odd handshakes.
  - `01-tls-primer.md` — the TLS record layer, Client/Server Hello framing, cipher
    suites, extensions, and GREASE (just enough to follow the rest).
  - `02-jarm-algorithm.md` — the ten probes as a matrix, what each axis tests, and
    the token → raw → hash data flow.
  - `03-clienthello-anatomy.md` — byte-by-byte Client Hello construction with
    length-field maps and the exact extension set/order.
  - `04-serverhello-and-hash.md` — Server Hello field offsets and the 62-char
    fuzzy-hash assembly (30 cipher/version chars + 32 SHA-256 chars).
  - `05-implementation-and-validation.md` — code map, the three silent bugs, and
    the validation method.

### Correctness notes (why this is "done right")
The initial from-scratch attempt failed three ways — one loud, two silent — and
all three are the kind that pass a casual "it runs and returns a hash" check:

1. **Malformed Client Hello (loud).** A fabricated extension, wrong bytes for
   `ec_point_formats` / `signature_algorithms`, and four missing extensions
   (`extended_master_secret`, `max_fragment_length`, `renegotiation_info`,
   `psk_key_exchange_modes`) caused servers to reject every probe with a TLS
   `decode_error` alert → an all-zero fingerprint. Fixed by rebuilding the exact
   extension set/order; the verification signal is the server switching from an
   alert to a Server Hello (9/10 probes for a strict server, with the TLS-1.3
   contradiction probe legitimately returning `handshake_failure`).
2. **`supported_versions` sent unconditionally (silent).** The extension must be
   emitted only on TLS-1.3 or `1.2_SUPPORT` probes; sending it on the
   `NO_SUPPORT` probes changes what they ask and drifts the fingerprint while the
   packets still parse.
3. **Hashing with the wrong cipher table (silent).** `cipher_code` must index
   JARM's separate **value-sorted** cipher table, not the offer-order list used in
   the Client Hello. Using the wrong table yields a deterministic, well-formed,
   62-char hash that matches no other JARM implementation — defeating the entire
   purpose (cross-tool `ssl.jarm:` pivoting).

**Validation.** With the free-tier Shodan key unable to run `ssl.jarm:` searches,
correctness was established two ways: (a) diffing cipher lists, `cipher_mung`,
extension bytes/order, Server Hello offsets, and the hash functions against the
canonical Salesforce reference; and (b) reproducing Google's publicly documented
fingerprint prefix `27d40d40d29d40d1dc42d43d00041d…` byte-for-byte.

### Operational
- JARM is **active** — it opens ten TCP connections to port 443. Run it only
  against authorised targets. The blocking socket work runs in an executor so it
  doesn't stall the async pipeline.

---

## [1.7.0] — 2026-07-08

Infrastructure-pivot release, completing the Phase 2 "modern recon sources" set.

### Added
- **Infrastructure pivot** (`scrapers/infra_pivot.py`, `infra_pivot` module) —
  fingerprints a target and pivots to sibling infrastructure two ways:
  - **Favicon hash** — Shodan's MurmurHash3-of-base64 favicon hash,
    reimplemented in pure Python (no native `mmh3` dependency; verified
    byte-for-byte against the reference). Pivots via Shodan `http.favicon.hash:`.
  - **TLS certificate** — leaf-cert SHA-256 fingerprint plus Subject Alternative
    Names via the stdlib `ssl` module. SANs are emitted as subdomains that feed
    the recursive pivot and takeover detector; pivots via Shodan
    `ssl.cert.serial:`. Sibling IPs from either pivot feed the graph.
- CLI `--modules infra_pivot` with a result panel; a web scan-form card and
  favicon/cert/sibling results rendering.

### Notes
- An active **JARM** TLS-stack fingerprint was scoped for this release but
  deferred: a from-scratch port produced malformed TLS Client Hellos, and a
  silently-wrong fingerprint is unacceptable in a security tool. The correct
  stdlib TLS-certificate pivot ships as the TLS-axis substitute; JARM will land
  later via a vetted reference implementation with published test vectors.
- Test suite grew to 44 tests (added MurmurHash3 vectors, favicon hashing,
  favicon-URL resolution, cert fingerprinting, and SAN scoping).

---

## [1.6.0] — 2026-07-07

Content-mining release. Two new passive recon modules extend the attack-surface
pipeline by mining what a target already exposes — its JavaScript and its
historical URLs — and feed the discoveries back into the v1.5.0 pivot, takeover,
and signature engines.

### Added
- **JavaScript secret & endpoint mining** (`scrapers/js_miner.py`, `js_mine`
  module) — fetches a target's page plus every linked and inline script and mines
  the JavaScript for leaked secrets (AWS/Google/Slack/GitHub/Stripe/Twilio/
  SendGrid keys, private keys, JWTs, and entropy-gated generic key/token
  assignments) and API endpoints (absolute URLs + root-relative API paths, with
  XML-namespace and asset-extension noise filtered). Secrets are **masked** in
  output so raw credentials are never written to the database or exports. Secret
  detectors mirror the exposed-secret signature templates.
- **Archive URL mining** (`scrapers/archive_miner.py`, `archive_mine` module) —
  passive historical URL discovery (gau/waybackurls lineage) from keyless sources
  (Wayback CDX, AlienVault OTX, URLScan) gathered concurrently with graceful
  degradation. Scopes URLs to the target, flags sensitive files/paths and
  parameterised endpoints, inventories query parameters, and emits the distinct
  historical subdomains seen across captures — which feed the recursive pivot and
  takeover detector.

### Changed
- **CLI `--modules`** now accepts `js_mine` and `archive_mine`, each with a
  dedicated result panel; both modules also appear as cards on the web scan form
  with tailored results rendering.
- **Test suite** grew to 39 tests (added JS-miner extraction/detection/entropy
  and archive parse/scope/classify coverage).

---

## [1.5.0] — 2026-07-07

Attack-surface pipeline release. PhantomSignal moves from a single-pass API
aggregator toward a continuous attack-surface platform: discovered assets now
feed back in automatically, exposures are matched by data-driven signatures, and
subdomain discovery/takeover detection land as first-class modules. All new
capability is opt-in and the default single-pass behaviour is unchanged.

### Added
- **Recursive entity-graph pivoting** (`intel/pivot.py`) — the orchestrator can now
  feed discovered IPs, subdomains, and emails back in as new targets via a
  breadth-first `RecursivePivotEngine` with dedup, depth, entity-budget, and
  eTLD+1 scope guards. Opt in through `run()` options (`recursive`, `max_depth`,
  `allow_cross_domain`). Turns the aggregator into a SpiderFoot-class expander.
- **Signature engine** (`intel/signatures/`) — a Nuclei-style YAML template engine
  with two modes: `match` (word/regex/keyword matchers over aggregated results)
  and `dork` (GHDB queries rendered scoped to the target). Ships GHDB
  config/secrets and exposed-panel dork packs plus subdomain-takeover and
  exposed-VCS/cloud-key match templates. Enable via the `signatures` option.
- **Passive subdomain enumeration at scale** (`scrapers/subdomain_enum.py`) — new
  `subdomain_enum` module. Keyless multi-source gathering (crt.sh, HackerTarget,
  AlienVault OTX passive DNS, Anubis) with graceful per-source degradation,
  permutation generation, wildcard-DNS detection + filtering, and concurrent
  resolve-validation. Emits results carrying A records and CNAMEs.
- **Active subdomain-takeover detection** (`scrapers/takeover.py`) — new `takeover`
  module. A can-i-take-over-xyz-style fingerprint DB plus active HTTP-body and
  NXDOMAIN confirmation, producing graded verdicts (vulnerable / candidate /
  suppressed) tuned to minimise false positives.
- **Attack-surface pipeline controls in the web UI** — the scan form gains a
  Recursive Pivot toggle (with depth + cross-domain sub-options) and a Signature
  Engine toggle, plus Subdomain Enum and Takeover Detect module cards. Results
  render dork findings as clickable searches, and signature/takeover findings
  with severity badges.
- **Test suite** (`tests/`) — the repository's first automated tests: 33 tests
  covering pivot entity-extraction and guards, signature matching/dork scoping,
  subdomain-enum parsing and wildcard filtering, and the takeover grading matrix.

### Changed
- **Tagline** — replaced *"See everything. Leave no trace."* with **"Map the
  surface. Own the signal."** across the CLI banner, README, homepage, HTML
  export footer, and ASCII-art scripts; the old line was contradicted by
  `ROBOTSTXT_OBEY` and a self-identifying User-Agent.
- **CLI `--modules`** now accepts `subdomain_enum` and `takeover`, with dedicated
  result panels for each.
- Added a `docs/assets` project gravatar and `scripts/render_gravatar.py`.

---

## [1.4.3] — 2026-06-10

### Fixed
- **Quick probe intel coverage** — `IntelOrchestrator._get_applicable_apis` was silently skipping applicable APIs for several target types. Username targets matched zero intel APIs (no branch existed for them). Email targets missed threat-intel, breach, and people-category sources. Domain targets missed email-category APIs (Hunter.io email discovery). IP targets missed dark-web sources (Intelligence X paste/leak search).

  Updated category sets per target type:
  - **IP** — `network | threat_intel | geolocation | vulnerability | dark_web`
  - **Email** — `email | breach | threat_intel | people`
  - **Domain** — `domain | threat_intel | email`
  - **Username** — `social | people` *(new branch)*

  All individual API implementations retain their own target-type guards and return `[]` gracefully for unsupported input, so no new noise is introduced.

---

## [1.4.2] — 2026-06-06

### Fixed
- Export commands now work immediately after install — `ExportManager`, `config`, and the `export` CLI command all default output to `/tmp` instead of `./exports`, preventing permission errors for users who haven't configured an output directory. Override with `PHANTOMSIGNAL_EXPORT_DIR` env var or `--output`.
- `RuntimeWarning: coroutine was never awaited` printed on every scan when modules were excluded from the pipeline — `_build_pipeline` now uses lazy factories so coroutines are only created for modules that will actually run.
- `scan --output` flag now treated as a directory path (not a file path), matching the documented behaviour.

---

## [1.4.1] — 2026-06-06

### Changed
- README updated to reflect v1.4.0 features — What's New section, API integrations table (46+ sources), architecture count

---

## [1.4.0] — 2026-06-06

### Added
- **16 new intelligence API integrations** — Twitch, Mastodon (4 federated instances), Keybase, Gravatar, HackerNews, Tumblr, Flickr, Spotify, Steam, VK, Telegram (public channels), Discord (user + server), Facebook/Meta Graph, EmailRep, Intelligence X (dark web / paste / breach), and Abstract API phone validation
- **Ghost Key invalid-key indicator** — TEST button in the Ghost Key Vault now detects HTTP 401/403 rejections and surfaces an amber `⚠ INVALID` badge on the key row with a targeted toast message, distinct from generic network failures (`✗ FAIL`)
- **`APIAuthError` exception** (`intel/apis/base.py`) — raised on 401/403 in `_get`; propagates through the orchestrator and is caught specifically by the test endpoint, keeping scan pipelines unaffected
- **WebSocket sync on late join** (`web/app.py`, `terminal.js`) — server emits current scan progress to clients that connect after a scan has already started; eliminates the stuck-at-0% progress bar on page load
- **Polling fallback for live results** (`results.html`) — a background `fetch` loop keeps the progress bar accurate even when SocketIO events are missed (slow connect, missed room join)

### Changed
- **AlienVault OTX timeout fix** — section requests (`general`, `reputation`, `geo`, `malware`, `passive_dns`) now run concurrently via `asyncio.gather` with an 8-second per-section timeout instead of sequentially; eliminates the consistent 30s timeout caused by the slow `reputation` endpoint
- **People aggregator** (`intel/people/aggregator.py`) — now runs free no-key sources as a fallback baseline when no paid people-intel APIs are configured; improved field merging for names, employers, social profiles, and phone numbers; native social API result types (`github_profile`, `twitter_profile`, etc.) mapped directly to social profile slots
- **Config env mappings** (`core/config.py`) — added env var bindings for all 16 new API integrations
- **Socket init timing** (`app.js`) — `initSocket()` called at module load (before `DOMContentLoaded`) so the results page can attach scan room listeners immediately; guarded against double-init
- **Scan start delay** (`core/engine.py`) — 1-second delay before first module fires, preventing WebSocket race where events are emitted before the browser has joined the scan room
- **`.gitignore`** — replaced explicit `.env.local` / `.env.production` entries with `.env.*` wildcard; added `!.env.example` exclusion so a template file can be committed safely; covers `.env.testing` and any future per-environment variants

### Fixed
- Ghost Key TEST showing `✓ OK` with 0 results for an invalid key (e.g. Shodan 403) — now correctly shows `⚠ INVALID`
- AlienVault consistently timing out on IP scans due to sequential section fetches exceeding the 30s orchestrator limit
- Progress bar stuck at 0% when navigating directly to a scan URL mid-run

---

## [1.3.3] — 2026-06-05

### Changed
- **Wordmark logo** — replaced block-character ghost mascot with a `PHANTOM / SIGNAL` slant-font wordmark (neon green glow) across the nav bar, page headings, empty states, and favicon; both words centered on a shared canvas
- **Ghost emoji** — swapped 🦉 → 👻 in UI templates and pre-rendered README SVG screenshots (`screenshot_dashboard.svg`, `screenshot_launch.svg`)
- **CSS sizing** — image sizing switched from height-based to width-based (`120px` nav, `180px` heading, `200px` empty state) to match the new wider image proportions

### Added
- `scripts/render_avatar.py` — source-of-truth script to regenerate the wordmark PNG assets (pyfiglet slant font + Pillow glow layers)
- `docs/assets/phantomsignal-avatar-transparent.png` — transparent variant of the wordmark for light backgrounds

### Removed
- `scripts/render_owl.py` and all owl PNG assets (`owl-ascii.png`, `owl-ascii-transparent.png`)

### Fixed
- Encrypted exporter file magic bytes updated `NOWL` → `NPHM`; legacy `NOWL` files remain readable for backwards compatibility

### Housekeeping
- `wheels/` added to `.gitignore` (offline pip wheel cache — not for version control)
- Dockerfile: optional crawler deps (`chromium`, `tesseract-ocr`) split into a fault-tolerant layer; added offline wheel install via `--find-links`

---

## [1.3.1] — 2026-06-04

### Changed
- **Author rebrand** — all author references updated from `packetsn1ffer` to `the-clipper` across package metadata, LICENSE, and inline credits.
- **GitHub Sponsors** — added sponsorship links to README, landing page, and `FUNDING.yml`.
- **Assets** — updated org avatar and asciinema recording to reflect PhantomSignal branding.

---

## [1.3.0] — 2026-05-31

### Added
- **Rich CLI scan output** — `phantomsignal scan <target>` now renders module-specific panels instead of a flat table: DNS intelligence (records, subdomains, SPF/DMARC/DNSSEC, cert transparency, zone transfer), port scan table (PORT · SERVICE · PROTO · VERSION · BANNER · RISK), tech stack (detected technologies, security header grade A–F, TLS info), exposed resources (status codes, sensitive path flags), network intel (GeoIP, ASN, TOR/VPN indicators), and a red anomaly callout panel. All panel right-borders are pinned to terminal width.
- **nmap integration in port scanner** — attempts `nmap -sV --version-intensity 7 -O --osscan-guess` for full version detection and OS fingerprinting; falls back silently to the pure-Python async TCP prober when nmap is absent or lacks privileges. Scan engine and OS guess shown in panel footer.
- **Expanded port coverage** — `COMMON_PORTS` grown from 56 → 99 ports covering low privileged and high-numbered services (WinRM, Webmin, InfluxDB, Radmin, and more). `DANGEROUS_PORTS` extended with WinRM, REXEC, RLOGIN, FINGER, RPCBIND, Radmin, and Webmin.
- **Web results type-aware rendering** — results page renders each result type as structured output matching CLI panels instead of raw JSON blobs. Covers open ports, OS detection, DNS records, email security, security posture grade, TLS, API endpoints, IP geolocation, and more.

### Changed
- **Quick probe** now runs all 5 CLI-default modules (`dns_recon`, `port_scan`, `tech_detect`, `api_hunt`, `intel`) — previously ran only 3.
- **Full mission form** — `web_crawl` unchecked by default to match CLI behaviour.
- **API route** empty-modules fallback uses the same 5-module default as CLI.
- **`.gitignore`** — `scans/` → `/scans/` to avoid shadowing `phantomsignal/web/templates/scans/`.

---

## [1.2.5] — 2026-05-30

### Fixed
- README demo images not rendering on PyPI — replaced relative `docs/assets/` paths with absolute `raw.githubusercontent.com` URLs

---

## [1.2.4] — 2026-05-30

### Changed
- Added `Homepage` and `Documentation` URLs pointing to phantomsignal.sh in PyPI project metadata

---

## [1.2.3] — 2026-05-30

### Fixed
- Web UI navbar brand link displayed "NIGHTOWL" instead of "PHANTOMSIGNAL"

---

## [1.2.2] — 2026-05-30

### Fixed
- `phantomsignal web` crash on all platforms — missing `allow_unsafe_werkzeug=True` in `socketio.run()` call in CLI entrypoint
- Windows asyncio compatibility — force `WindowsSelectorEventLoopPolicy` on Python 3.10+ to prevent `aiodns` conflict with `ProactorEventLoop`

---

## [1.2.1] — 2026-05-30

### Fixed
- PyPI project description updated with correct asciinema recording URL and PyPI badge

---

## [1.2.0] — 2026-05-30

### Changed
- **Project renamed from NightOwl to PhantomSignal** — all references updated across codebase, docs, config, and assets
- Domain migrated from `owlrecon.io` → `phantomsignal.sh`; DNS configured with GitHub Pages A records
- GitHub org renamed `nightowl-osint` → `phantomsignal`; repo renamed `nightowl` → `phantomsignal`
- Python package renamed `nightowl` → `phantomsignal`; CLI entry point `nightowl` → `phantomsignal` (`owl` alias preserved)
- Config directory `~/.nightowl/` → `~/.phantomsignal/`; config file `nightowl.yaml` → `phantomsignal.yaml`
- Database default `nightowl.db` → `phantomsignal.db`
- Environment variable prefix `NIGHTOWL_*` → `PHANTOMSIGNAL_*`
- ASCII banner art regenerated for PHANTOMSIGNAL in `__init__.py`, README, and all demo assets
- Owl PNG graphic updated — footer label changed from "NightOwl" to "PhantomSignal" in both dark and transparent variants
- Demo GIF and asciinema cast regenerated with PHANTOMSIGNAL banner and `phantomsignal` CLI command
- SVG screenshots regenerated with updated PHANTOMSIGNAL branding throughout
- GitHub Pages landing site fully rebranded — nav, hero title, footer, and og tags
- GitHub org profile README rebranded with new ASCII art, updated badges and links
- GitHub repo About description and homepage URL updated to `phantomsignal.sh`
- Contact email updated to `security@phantomsignal.sh` across all docs

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
- GitHub Pages project landing site at `https://phantomsignal.sh` (`docs/`)
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
- Initial release of PhantomSignal — open-source OSINT intelligence framework
- CLI interface (`phantomsignal`) with ghost run profiles: Quick Probe, Standard Recon, Deep Dive, Ghost Mode
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
- Repository URLs corrected to `phantomsignal/phantomsignal` across all files and badge links

---

[Unreleased]: https://github.com/getphantomsignal/phantomsignal/compare/v1.4.2...HEAD
[1.4.2]: https://github.com/getphantomsignal/phantomsignal/compare/v1.4.1...v1.4.2
[1.4.1]: https://github.com/getphantomsignal/phantomsignal/compare/v1.4.0...v1.4.1
[1.4.0]: https://github.com/getphantomsignal/phantomsignal/compare/v1.3.3...v1.4.0
[1.3.3]: https://github.com/getphantomsignal/phantomsignal/compare/v1.3.1...v1.3.3
[1.3.1]: https://github.com/getphantomsignal/phantomsignal/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/getphantomsignal/phantomsignal/compare/v1.2.5...v1.3.0
[1.2.5]: https://github.com/getphantomsignal/phantomsignal/compare/v1.2.4...v1.2.5
[1.2.4]: https://github.com/getphantomsignal/phantomsignal/compare/v1.2.3...v1.2.4
[1.2.3]: https://github.com/getphantomsignal/phantomsignal/compare/v1.2.2...v1.2.3
[1.2.2]: https://github.com/getphantomsignal/phantomsignal/compare/v1.2.1...v1.2.2
[1.2.1]: https://github.com/getphantomsignal/phantomsignal/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/getphantomsignal/phantomsignal/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/getphantomsignal/phantomsignal/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/getphantomsignal/phantomsignal/releases/tag/v1.0.0
