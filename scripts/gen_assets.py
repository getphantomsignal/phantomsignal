#!/usr/bin/env python3
"""Generate OwlScan demo assets: SVG screenshots + asciinema cast file."""

import json
import math
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich.padding import Padding
from rich.style import Style
from rich.terminal_theme import TerminalTheme, MONOKAI

# ---------------------------------------------------------------------------
# Cyberpunk terminal theme (dark bg, neon accent)
# ---------------------------------------------------------------------------
OWLSCAN_THEME = TerminalTheme(
    background=(10, 10, 20),
    foreground=(0, 243, 255),
    normal=[
        (10, 10, 20),
        (220, 30, 80),
        (0, 255, 65),
        (255, 200, 0),
        (60, 100, 255),
        (176, 38, 255),
        (0, 243, 255),
        (180, 180, 200),
    ],
    bright=[
        (50, 50, 70),
        (255, 60, 100),
        (0, 255, 100),
        (255, 230, 50),
        (100, 150, 255),
        (200, 80, 255),
        (0, 255, 255),
        (255, 255, 255),
    ],
)

DOCS = Path(__file__).parent.parent / "docs" / "assets"
DOCS.mkdir(parents=True, exist_ok=True)


def make_console(width: int = 110) -> Console:
    return Console(record=True, width=width, force_terminal=True)


# ---------------------------------------------------------------------------
# Screenshot 1: Dashboard / Shadow Grid
# ---------------------------------------------------------------------------
def gen_dashboard():
    c = make_console(110)

    c.print()
    c.print(
        "  [bold bright_cyan]🦉 OWLSCAN[/] [dim cyan]//[/] [bold bright_green]SHADOW GRID[/]"
        "                         [dim]Operative command center — all systems nominal[/]"
    )
    c.print(
        "[dim cyan]" + "─" * 108 + "[/]"
    )
    c.print()

    # Stat cards row
    stats = [
        ("◫", "42", "TOTAL\nMISSIONS", "bright_green"),
        ("◉", " 3", "ACTIVE\nGHOSTS",   "bright_cyan"),
        ("⬡", "1,337", "SIGNALS\nCAPTURED", "bright_magenta"),
        ("⚠", " 2", "CRITICAL\nTHREATS", "bright_red"),
        ("⚙", " 8", "APIS\nONLINE",   "bright_yellow"),
    ]
    cards = []
    for icon, val, label, col in stats:
        t = Text()
        t.append(f"  {icon} ", style=f"bold {col}")
        t.append(f"{val}\n", style=f"bold {col}")
        t.append(f"  {label}", style="dim")
        cards.append(Panel(t, border_style=col, width=20))
    c.print(Columns(cards, equal=True, expand=False, padding=(0, 1)))

    c.print()

    # Recent scans table
    tbl = Table(
        title="◫  RECENT GHOST RUNS",
        title_style="bold bright_green",
        border_style="cyan",
        header_style="bold cyan",
        width=72,
    )
    tbl.add_column("TARGET", style="bright_white", min_width=22)
    tbl.add_column("TYPE",   style="cyan",         min_width=14)
    tbl.add_column("STATUS", min_width=12)
    tbl.add_column("SCORE",  min_width=8)
    tbl.add_column("THREAT", min_width=10)

    rows = [
        ("example.com",   "web_recon",    "[bold green]COMPLETE[/]",  "72", "[bold yellow]MEDIUM[/]"),
        ("198.51.100.42", "ip_recon",     "[bold cyan]▶ RUNNING[/]",  "—",  "[dim]SCANNING[/]"),
        ("corp-api.io",   "domain_recon", "[bold green]COMPLETE[/]",  "89", "[bold red]HIGH[/]"),
        ("john.doe@ex.co","people_intel", "[bold green]COMPLETE[/]",  "45", "[bold green]LOW[/]"),
        ("darknet-hub.to","full_spectrum", "[bold red]FAILED[/]",     "—",  "[dim]UNKNOWN[/]"),
    ]
    for target, typ, status, score, threat in rows:
        tbl.add_row(target, typ, status, score, threat)

    # Live feed panel
    live = Text()
    live.append("[OWLSCAN] ", style="bold bright_cyan")
    live.append("Signal established. Grid online.\n", style="bright_white")
    live.append("[SYSTEM]   ", style="bold bright_green")
    live.append("3 active ghost runs in progress.\n", style="dim")
    live.append("[DNS]      ", style="bold bright_yellow")
    live.append("Resolving corp-api.io... ", style="dim")
    live.append("OK\n", style="bold bright_green")
    live.append("[PORT]     ", style="bold bright_yellow")
    live.append("198.51.100.42:80  ", style="dim")
    live.append("OPEN", style="bold bright_green")
    live.append(" nginx/1.24\n", style="dim cyan")
    live.append("[PORT]     ", style="bold bright_yellow")
    live.append("198.51.100.42:443 ", style="dim")
    live.append("OPEN", style="bold bright_green")
    live.append(" TLS1.3\n", style="dim cyan")
    live.append("[SHODAN]   ", style="bold bright_magenta")
    live.append("2 vulnerabilities found\n", style="bold bright_red")
    live.append("[INTEL]    ", style="bold bright_magenta")
    live.append("VirusTotal: ", style="dim")
    live.append("CLEAN ✓\n", style="bold bright_green")
    live.append("[SYSTEM]   ", style="bold bright_green")
    live.append("Awaiting next operative command...", style="dim")

    live_panel = Panel(
        live,
        title="◉  LIVE FEED  [blink]█[/]",
        title_align="left",
        border_style="bright_cyan",
        width=35,
    )

    c.print(Columns([tbl, live_panel], padding=(0, 1)))

    c.print()
    c.print(
        "  [dim cyan]◈ QUICK PROBE:[/]  "
        "[bright_white]TARGET // IP · DOMAIN · URL · EMAIL · USERNAME[/]  "
        "[dim][[/][bold bright_green] PROBE [/][dim]][/]"
    )
    c.print()

    c.save_svg(DOCS / "screenshot_dashboard.svg", title="OwlScan — Shadow Grid", theme=OWLSCAN_THEME)
    print("✓  screenshot_dashboard.svg")


# ---------------------------------------------------------------------------
# Screenshot 2: Launch Ghost Run (new scan)
# ---------------------------------------------------------------------------
def gen_launch():
    c = make_console(110)

    c.print()
    c.print(
        "  [bold bright_cyan]🦉 OWLSCAN[/] [dim cyan]//[/] [bold bright_green]LAUNCH GHOST RUN[/]"
        "                    [dim]Configure your recon parameters, Operative[/]"
    )
    c.print("[dim cyan]" + "─" * 108 + "[/]")
    c.print()

    # Target input
    c.print(
        Panel(
            "[dim cyan]◈  TARGET IDENTIFIER[/]\n"
            "[bold bright_white on grey7]  ENTER TARGET // IP · DOMAIN · URL · EMAIL · USERNAME               "
            "                           [/] [bright_cyan]● DOMAIN[/]",
            title="[bold bright_green]◈  MARK ACQUISITION[/]",
            border_style="bright_green",
        )
    )
    c.print()

    # Profile cards
    profiles = [
        ("⚡", "QUICK PROBE",     "Fast surface scan.\nDNS, top ports, tech stack.", "~30s",   "bright_yellow", False),
        ("◈", "STANDARD RECON",  "Balanced depth.\nAll modules, moderate crawl.",   "~2-5min", "bright_green",  True),
        ("⬡", "DEEP DIVE",       "Thorough crawl, full port scan,\nall intel APIs.","~10-30min","bright_magenta",False),
        ("👻","GHOST MODE",      "Low-and-slow, identity rotation,\nmin footprint.", "Variable","bright_white",  False),
    ]
    cards = []
    for icon, name, desc, time_, col, sel in profiles:
        border = col if sel else "dim"
        inner = Text()
        inner.append(f"  {icon}\n", style=f"bold {col}")
        inner.append(f"  {name}\n", style=f"bold {'bright_white' if sel else col}")
        inner.append(f"  {desc}\n", style="dim")
        inner.append(f"  {time_}", style=f"dim {col}")
        cards.append(Panel(inner, border_style=border, width=26, subtitle="[bold bright_green]✓ SELECTED[/]" if sel else ""))
    c.print(Columns(cards, equal=True, expand=False, padding=(0, 1)))
    c.print()

    # Module grid
    modules = [
        ("🌐", "DNS RECON",    "Records, subdomains, zone transfer, SPF/DMARC", True),
        ("🔌", "PORT SCANNER", "Async TCP scan with banner grabbing",            True),
        ("🔬", "TECH DETECTOR","Framework, CMS, CDN, WAF, security headers",    True),
        ("🎯", "API HUNTER",   "Endpoints, GraphQL, swagger, admin panels",      True),
        ("🕷", "WEB CRAWLER",  "Links, forms, emails, JS, comments",             True),
        ("📡", "INTEL APIS",   "Shodan, VirusTotal, AbuseIPDB & more",          True),
    ]
    mod_cols = []
    for icon, name, desc, active in modules:
        col = "bright_green" if active else "dim"
        t = Text()
        t.append(f" {icon} {name}\n", style=f"bold {col}")
        t.append(f" {desc}", style="dim")
        mod_cols.append(Panel(t, border_style=col, width=34))
    c.print("[dim cyan]◫  RECON MODULES[/]  [dim][ TOGGLE ALL ][/]")
    c.print(Columns(mod_cols[:3], equal=True, expand=False, padding=(0, 0)))
    c.print(Columns(mod_cols[3:], equal=True, expand=False, padding=(0, 0)))

    c.print()
    c.print("  " + "[bold bright_green on grey7]  ◈  INITIATE GHOST RUN  [/]", justify="left")
    c.print()

    c.save_svg(DOCS / "screenshot_launch.svg", title="OwlScan — Launch Ghost Run", theme=OWLSCAN_THEME)
    print("✓  screenshot_launch.svg")


# ---------------------------------------------------------------------------
# Screenshot 3: Scan results
# ---------------------------------------------------------------------------
def gen_results():
    c = make_console(110)

    c.print()
    c.print(
        "  [dim cyan]GHOST RUNS ›[/] [bold bright_white]example.com[/]  "
        "[bold bright_green]◉ COMPLETE[/]"
    )
    c.print()

    # Meta strip
    meta = (
        "[dim]TYPE[/] [cyan]web_recon[/]   "
        "[dim]PROFILE[/] [cyan]standard[/]   "
        "[dim]RESULTS[/] [bold bright_cyan]247[/]   "
        "[dim]DURATION[/] [cyan]4m 12s[/]   "
        "[dim]SHADOW SCORE[/] [bold bright_red]72[/][dim]/100[/]   "
        "[dim]THREAT[/] [bold bright_yellow]MEDIUM[/]"
    )
    c.print(Panel(meta, border_style="bright_cyan"))
    c.print()

    # Findings table
    tbl = Table(
        title="⬡  CAPTURED SIGNALS",
        title_style="bold bright_magenta",
        border_style="magenta",
        header_style="bold magenta",
        width=108,
    )
    tbl.add_column("MODULE",   style="bright_cyan",  min_width=14)
    tbl.add_column("TYPE",     style="cyan",          min_width=18)
    tbl.add_column("VALUE",    style="bright_white",  min_width=36)
    tbl.add_column("SEVERITY", min_width=10)
    tbl.add_column("SOURCE",   style="dim",           min_width=14)

    findings = [
        ("PORT_SCAN",   "open_port",        "443/tcp — TLS 1.3 (nginx/1.24.0)",   "[bold bright_green]INFO[/]",     "async_scanner"),
        ("PORT_SCAN",   "open_port",        "80/tcp  — HTTP  (redirect → HTTPS)",   "[bold bright_green]INFO[/]",     "async_scanner"),
        ("PORT_SCAN",   "open_port",        "8080/tcp — Tomcat/9.0.70 admin panel", "[bold bright_red]HIGH[/]",      "async_scanner"),
        ("TECH_DETECT", "framework",        "WordPress 6.4.2",                      "[bold bright_yellow]MEDIUM[/]",  "wappalyzer"),
        ("TECH_DETECT", "security_header",  "X-Frame-Options: MISSING",             "[bold bright_yellow]MEDIUM[/]",  "header_scan"),
        ("TECH_DETECT", "security_header",  "Content-Security-Policy: MISSING",     "[bold bright_yellow]MEDIUM[/]",  "header_scan"),
        ("DNS_RECON",   "subdomain",        "dev.example.com  → 203.0.113.44",     "[bold bright_green]INFO[/]",     "brute_force"),
        ("DNS_RECON",   "subdomain",        "api.example.com  → 198.51.100.1",     "[bold bright_green]INFO[/]",     "crt.sh"),
        ("DNS_RECON",   "spf_issue",        "SPF record missing — spoofable",       "[bold bright_red]HIGH[/]",      "dns_recon"),
        ("INTEL_API",   "shodan_vuln",      "CVE-2023-44487 (HTTP/2 Rapid Reset)",  "[bold bright_red]CRITICAL[/]",  "shodan"),
        ("INTEL_API",   "threat_intel",     "VirusTotal: 0/94 — CLEAN",             "[bold bright_green]INFO[/]",     "virustotal"),
        ("WEB_CRAWL",   "email_found",      "admin@example.com",                    "[bold bright_yellow]MEDIUM[/]",  "web_crawl"),
        ("API_HUNT",    "endpoint_found",   "/api/v1/users — no auth required",     "[bold bright_red]HIGH[/]",      "api_hunter"),
        ("API_HUNT",    "endpoint_found",   "/graphql — introspection enabled",     "[bold bright_yellow]MEDIUM[/]",  "api_hunter"),
    ]
    for mod, typ, val, sev, src in findings:
        tbl.add_row(mod, typ, val, sev, src)

    c.print(tbl)
    c.print()
    c.print(
        "  [dim]↓ EXPORT INTEL[/]  [dim]·[/]  "
        "[bold bright_magenta]JSON[/] [dim]CSV[/] [dim]HTML[/] [dim]PDF[/] "
        "[dim]STIX[/] [dim]XML[/] [dim]XLSX[/]"
    )
    c.print()

    c.save_svg(DOCS / "screenshot_results.svg", title="OwlScan — Scan Results", theme=OWLSCAN_THEME)
    print("✓  screenshot_results.svg")


# ---------------------------------------------------------------------------
# Screenshot 4: CLI output
# ---------------------------------------------------------------------------
def gen_cli():
    c = make_console(100)

    lines = [
        ("", "dim",                 ""),
        ("$ owlscan scan example.com --profile standard --format html", "bold bright_white", ""),
        ("", "", ""),
        (" ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗ ██╗    ██╗██╗", "bright_cyan", ""),
        (" ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔═══██╗██║    ██║██║", "bright_cyan", ""),
        (" ██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║   ██║██║ █╗ ██║██║", "bright_cyan", ""),
        (" ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║   ██║██║███╗██║██║", "cyan", ""),
        (" ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╔╝╚███╔███╔╝███████╗", "cyan", ""),
        (" ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝", "dim cyan", ""),
        ("         >> OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK <<", "bright_green", ""),
        ('                 "See everything. Leave no trace."', "dim green", ""),
        ("", "", ""),
        (" ◈  Target      : example.com                (domain)", "bright_white", ""),
        (" ◈  Profile     : standard                   (~2-5 min)", "bright_white", ""),
        (" ◈  Modules     : dns_recon port_scan tech_detect api_hunt web_crawl intel", "bright_white", ""),
        (" ◈  Export      : HTML report", "bright_white", ""),
        ("", "", ""),
        (" [00:00] ◉  Initializing recon engine...", "bright_cyan", ""),
        (" [00:01] 🌐  DNS RECON           → Resolving A/AAAA/MX/NS/TXT/SOA...", "bright_yellow", ""),
        (" [00:02]    ✓  A record: 93.184.216.34", "bright_green", ""),
        (" [00:02]    ✓  MX: mail.example.com (priority 10)", "bright_green", ""),
        (" [00:03]    ✓  Subdomains found via crt.sh: api · dev · mail · static", "bright_green", ""),
        (" [00:04]    ⚠  SPF record MISSING — mail spoofing possible", "bright_red", ""),
        (" [00:05] 🔌  PORT SCANNER        → Scanning top 1000 ports...", "bright_yellow", ""),
        (" [00:08]    ✓  80/tcp   OPEN  nginx/1.24.0 (redirect → HTTPS)", "bright_green", ""),
        (" [00:08]    ✓  443/tcp  OPEN  TLS 1.3 / nginx/1.24.0", "bright_green", ""),
        (" [00:09]    !  8080/tcp OPEN  Apache Tomcat/9.0.70 — ADMIN PANEL EXPOSED", "bright_red", ""),
        (" [00:12] 🔬  TECH DETECTOR       → Fingerprinting stack...", "bright_yellow", ""),
        (" [00:13]    ✓  CMS: WordPress 6.4.2 | CDN: Cloudflare", "bright_green", ""),
        (" [00:13]    ⚠  Missing headers: X-Frame-Options, Content-Security-Policy", "bright_yellow", ""),
        (" [00:14] 🎯  API HUNTER          → Probing endpoints...", "bright_yellow", ""),
        (" [00:16]    !  /api/v1/users — No authentication required", "bright_red", ""),
        (" [00:17]    !  /graphql       — Introspection enabled", "bright_yellow", ""),
        (" [00:18] 🕷   WEB CRAWLER        → Crawling depth 2...", "bright_yellow", ""),
        (" [00:42]    ✓  Harvested: 312 links · 14 emails · 3 phone numbers", "bright_green", ""),
        (" [00:43] 📡  INTEL APIS          → Querying 8 configured APIs...", "bright_yellow", ""),
        (" [00:44]    ✓  Shodan: 3 open ports, 1 CVE (CVE-2023-44487 CRITICAL)", "bright_red", ""),
        (" [00:45]    ✓  VirusTotal: 0/94 — CLEAN", "bright_green", ""),
        (" [00:46]    ✓  AbuseIPDB: confidence 0% — NOT FLAGGED", "bright_green", ""),
        ("", "", ""),
        (" ════════════════════════════════════════════════════", "dim cyan", ""),
        (" ◈  GHOST RUN COMPLETE  ·  4m 12s  ·  247 signals", "bold bright_green", ""),
        (" ════════════════════════════════════════════════════", "dim cyan", ""),
        (" ⚠  SHADOW SCORE: 72/100  ·  THREAT LEVEL: MEDIUM", "bold bright_yellow", ""),
        ("    ▸ 2 HIGH findings   1 CRITICAL finding", "bright_red", ""),
        ("    ▸ Admin panel exposed (8080) — remediate immediately", "bright_red", ""),
        ("    ▸ SPF record missing — email spoofing risk", "bright_yellow", ""),
        (" ✓  Report saved: ./reports/example.com_20260526.html", "bright_cyan", ""),
        ("", "", ""),
    ]

    for text, style, _ in lines:
        if style:
            c.print(text, style=style, highlight=False)
        else:
            c.print(text, highlight=False)

    c.save_svg(DOCS / "screenshot_cli.svg", title="OwlScan CLI", theme=OWLSCAN_THEME)
    print("✓  screenshot_cli.svg")


# ---------------------------------------------------------------------------
# Asciinema v2 cast file
# ---------------------------------------------------------------------------
def gen_cast():
    """Write a synthetic asciinema v2 cast file."""
    header = {
        "version": 2,
        "width": 100,
        "height": 38,
        "timestamp": 1748304000,
        "title": "OwlScan OSINT Framework — Live Demo",
        "env": {"TERM": "xterm-256color", "SHELL": "/bin/zsh"},
    }

    ESC = ""
    R = ESC + "[0m"

    def neon(s): return f"{ESC}[1;96m{s}{R}"
    def green(s): return f"{ESC}[1;92m{s}{R}"
    def yellow(s): return f"{ESC}[1;93m{s}{R}"
    def red(s): return f"{ESC}[1;91m{s}{R}"
    def cyan(s): return f"{ESC}[96m{s}{R}"
    def dim(s): return f"{ESC}[2m{s}{R}"
    def bold(s): return f"{ESC}[1m{s}{R}"
    def magenta(s): return f"{ESC}[1;95m{s}{R}"

    BANNER = (
        f"{neon(' ███╗   ██╗██╗ ██████╗ ██╗  ██╗████████╗ ██████╗ ██╗    ██╗██╗')}\r\n"
        f"{neon(' ████╗  ██║██║██╔════╝ ██║  ██║╚══██╔══╝██╔═══██╗██║    ██║██║')}\r\n"
        f"{neon(' ██╔██╗ ██║██║██║  ███╗███████║   ██║   ██║   ██║██║ █╗ ██║██║')}\r\n"
        f"{cyan(' ██║╚██╗██║██║██║   ██║██╔══██║   ██║   ██║   ██║██║███╗██║██║')}\r\n"
        f"{cyan(' ██║ ╚████║██║╚██████╔╝██║  ██║   ██║   ╚██████╔╝╚███╔███╔╝███████╗')}\r\n"
        f"{dim(' ╚═╝  ╚═══╝╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝  ╚══╝╚══╝ ╚══════╝')}\r\n"
        f"{green('         >> OPEN-SOURCE OSINT INTELLIGENCE FRAMEWORK <<')}\r\n"
        f'{dim(chr(34) + "See everything. Leave no trace." + chr(34))}\r\n'
    )

    events = []
    t = 0.0

    def out(text, delay=0.0):
        nonlocal t
        t += delay
        events.append([round(t, 3), "o", text])

    def line(text, delay=0.08):
        out(text + "\r\n", delay)

    def prompt(delay=0.5):
        nonlocal t
        t += delay
        out(f"{green('┌──(')}owlscan㉿phantom{green(')')} {dim('~')}\r\n{green('└─$ ')}")

    # Start
    prompt(1.0)
    # Typing the command
    cmd = "owlscan scan example.com --profile standard --format html"
    for ch in cmd:
        out(ch, 0.06)
    out("\r\n", 0.4)

    # Banner
    out("\r\n", 0.3)
    out(BANNER, 0.1)
    out("\r\n", 0.2)

    line(f" {neon('◈')}  Target   : {bold('example.com')}  {dim('(domain)')}", 0.05)
    line(f" {neon('◈')}  Profile  : {bold('standard')}     {dim('(~2-5 min)')}", 0.05)
    line(f" {neon('◈')}  Modules  : {cyan('dns_recon port_scan tech_detect api_hunt web_crawl intel')}", 0.05)
    line(f" {neon('◈')}  Export   : {cyan('HTML report')}", 0.05)
    out("\r\n", 0.3)

    line(f" {dim('[00:00]')} {cyan('◉')}  Initializing recon engine...", 0.3)
    line(f" {dim('[00:01]')} 🌐  {yellow('DNS RECON')}           → Resolving A/AAAA/MX/NS/TXT/SOA...", 0.6)
    line(f" {dim('[00:02]')}    {green('✓')}  A record: 93.184.216.34", 0.8)
    line(f" {dim('[00:02]')}    {green('✓')}  MX: mail.example.com (priority 10)", 0.5)
    line(f" {dim('[00:03]')}    {green('✓')}  Subdomains via crt.sh: {cyan('api · dev · mail · static')}", 0.8)
    line(f" {dim('[00:04]')}    {red('⚠')}  SPF record MISSING — mail spoofing possible", 0.9)
    line(f" {dim('[00:05]')} 🔌  {yellow('PORT SCANNER')}        → Scanning top 1000 ports...", 0.5)
    line(f" {dim('[00:08]')}    {green('✓')}  80/tcp   {green('OPEN')}  {dim('nginx/1.24.0  (redirect → HTTPS)')}", 1.8)
    line(f" {dim('[00:08]')}    {green('✓')}  443/tcp  {green('OPEN')}  {dim('TLS 1.3 / nginx/1.24.0')}", 0.4)
    line(f" {dim('[00:09]')}    {red('!')}  8080/tcp {red('OPEN')}  {red('Apache Tomcat/9.0.70 — ADMIN PANEL EXPOSED')}", 0.6)
    line(f" {dim('[00:12]')} 🔬  {yellow('TECH DETECTOR')}       → Fingerprinting stack...", 1.2)
    line(f" {dim('[00:13]')}    {green('✓')}  CMS: WordPress 6.4.2  |  CDN: Cloudflare", 0.7)
    line(f" {dim('[00:13]')}    {yellow('⚠')}  Missing headers: X-Frame-Options, Content-Security-Policy", 0.4)
    line(f" {dim('[00:14]')} 🎯  {yellow('API HUNTER')}          → Probing endpoints...", 0.5)
    line(f" {dim('[00:16]')}    {red('!')}  /api/v1/users  — No authentication required", 1.4)
    line(f" {dim('[00:17]')}    {yellow('!')}  /graphql       — Introspection enabled", 0.6)
    line(f" {dim('[00:18]')} 🕷   {yellow('WEB CRAWLER')}         → Crawling depth 2...", 0.5)
    line(f" {dim('[00:42]')}    {green('✓')}  Harvested: 312 links · 14 emails · 3 phones", 8.0)
    line(f" {dim('[00:43]')} 📡  {yellow('INTEL APIS')}          → Querying 8 configured APIs...", 0.4)
    line(f" {dim('[00:44]')}    {green('✓')}  Shodan: 3 ports, {red('1 CVE (CVE-2023-44487 CRITICAL)')}", 0.8)
    line(f" {dim('[00:45]')}    {green('✓')}  VirusTotal: 0/94 — {green('CLEAN')}", 0.5)
    line(f" {dim('[00:46]')}    {green('✓')}  AbuseIPDB: confidence 0% — {green('NOT FLAGGED')}", 0.5)

    out("\r\n", 0.3)
    line(f" {dim('═' * 52)}", 0.2)
    line(f" {green('◈')}  {bold(green('GHOST RUN COMPLETE'))}  ·  4m 12s  ·  247 signals", 0.2)
    line(f" {dim('═' * 52)}", 0.1)
    line(f" {yellow('⚠')}  SHADOW SCORE: {red('72/100')}  ·  THREAT LEVEL: {yellow('MEDIUM')}", 0.2)
    line(f"    {red('▸')} 2 HIGH findings   1 CRITICAL finding", 0.2)
    line(f"    {red('▸')} Admin panel exposed (8080) — remediate immediately", 0.1)
    line(f"    {yellow('▸')} SPF record missing — email spoofing risk", 0.1)
    line(f" {cyan('✓')}  Report saved: {cyan('./reports/example.com_20260526.html')}", 0.3)
    out("\r\n", 0.5)
    prompt(1.0)

    cast_path = DOCS / "demo.cast"
    with open(cast_path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for event in events:
            f.write(json.dumps(event) + "\n")

    print(f"✓  demo.cast  ({len(events)} events, {t:.1f}s runtime)")


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print("Generating OwlScan demo assets...")
    gen_dashboard()
    gen_launch()
    gen_results()
    gen_cli()
    gen_cast()
    print(f"\nAll assets written to:  {DOCS}")
