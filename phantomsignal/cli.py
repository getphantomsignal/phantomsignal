"""
PhantomSignal CLI — Ghost Terminal Interface
Operative command-line control for the shadow grid.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import json
import sys
import platform
from pathlib import Path
from typing import Optional

# On Windows, Python 3.10+ defaults to ProactorEventLoop which is incompatible
# with aiodns used during scans. Force SelectorEventLoop on Windows.
if platform.system() == "Windows":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import print as rprint

from phantomsignal import __version__, BANNER, DISCLAIMER

console = Console(highlight=True)


# ── Scan result display helpers ──────────────────────────────────────────────

def _pw(con) -> int:
    """Panel width — full terminal width, minimum 80."""
    return max(con.width or 80, 80)


def _dns_panel(con, results):
    lines = []

    ips = [r["data"]["ip"] for r in results if r["result_type"] == "ip_address"]
    if ips:
        lines.append(f"[bold cyan]IPs:[/bold cyan] {' · '.join(ips[:10])}")

    for r in results:
        if r["result_type"] == "dns_records":
            recs = r["data"].get("records", {})
            labels = {"MX": "Mail (MX)", "NS": "Nameservers", "TXT": "TXT Records"}
            for rtype, label in labels.items():
                vals = recs.get(rtype, [])
                if vals:
                    lines.append(f"[bold cyan]{label}:[/bold cyan] {' · '.join(v[:60] for v in vals[:4])}")
            break

    for r in results:
        if r["result_type"] == "subdomain_summary":
            count = r["data"].get("discovered_count", 0)
            subs = r["data"].get("subdomains", [])
            suffix = " …" if len(subs) > 8 else ""
            lines.append(f"[bold cyan]Subdomains:[/bold cyan] {count} discovered — {', '.join(subs[:8])}{suffix}")
            break

    ct_hits = [r for r in results if r["result_type"] == "cert_transparency"]
    if ct_hits:
        lines.append(f"[bold cyan]Cert Transparency:[/bold cyan] {len(ct_hits)} certificate record(s) found")

    for r in results:
        if r["result_type"] == "email_security":
            d = r["data"]
            spf   = "[green]✓ SPF[/green]"   if d.get("spf_configured")   else "[red]✗ SPF[/red]"
            dmarc = "[green]✓ DMARC[/green]" if d.get("dmarc_configured") else "[red]✗ DMARC[/red]"
            spoof = "  [bold red]⚠ DOMAIN SPOOFABLE[/bold red]" if d.get("spoofable") else ""
            lines.append(f"[bold cyan]Email Security:[/bold cyan] {spf}  {dmarc}{spoof}")
            break

    for r in results:
        if r["result_type"] == "dnssec":
            enabled = r["data"].get("dnssec_enabled", False)
            lines.append(f"[bold cyan]DNSSEC:[/bold cyan] {'[green]enabled[/green]' if enabled else '[yellow]not enabled[/yellow]'}")
            break

    zt = [r for r in results if r["result_type"] == "zone_transfer" and r["data"].get("vulnerable")]
    if zt:
        ns = zt[0]["data"].get("nameserver", "?")
        lines.append(f"[bold red]⚠ ZONE TRANSFER VULNERABLE:[/bold red] {ns} leaks full zone")

    nsec = next((r for r in results if r["result_type"] == "nsec_zone_walk"), None)
    if nsec:
        lines.append(f"[bold red]⚠ NSEC ZONE WALK:[/bold red] "
                     f"{nsec['data']['names_found']} names enumerated via DNSSEC NSEC chain")
    ptr = next((r for r in results if r["result_type"] == "ptr_sweep_summary"), None)
    if ptr:
        lines.append(f"[bold cyan]PTR sweep:[/bold cyan] {ptr['data']['resolved']} host(s) "
                     f"in {ptr['data']['netblock']}")
    snoop = next((r for r in results if r["result_type"] == "dns_cache_snoop"), None)
    if snoop:
        lines.append(f"[bold red]⚠ OPEN RESOLVER / CACHE SNOOP:[/bold red] "
                     f"{snoop['data']['nameserver']} — {len(snoop['data']['cached_domains'])} cached")

    if lines:
        con.print(Panel("\n".join(lines), title="[bold green]◈ DNS INTELLIGENCE[/bold green]",
                        border_style="green", padding=(0, 2), width=_pw(con)))


def _subdomain_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "subdomain_summary"), None)
    if not summary:
        return
    d = summary["data"]
    subs = d.get("subdomains", [])
    lines = []
    src = d.get("sources", {})
    src_str = "  ".join(f"{k}:{v}" for k, v in src.items()) if src else "—"
    lines.append(f"[bold cyan]Discovered:[/bold cyan] {d.get('discovered_count', 0)}"
                 f"  ([dim]{d.get('candidates_tested', 0)} candidates tested[/dim])")
    lines.append(f"[bold cyan]Sources:[/bold cyan] {src_str}")
    if d.get("wildcard_dns"):
        lines.append("[yellow]⚠ Wildcard DNS present — false positives filtered[/yellow]")
    cname_hits = [r for r in results
                  if r["result_type"] == "subdomain" and r["data"].get("cnames")]
    if cname_hits:
        lines.append(f"[bold cyan]CNAME records:[/bold cyan] {len(cname_hits)} "
                     "([dim]takeover-signature candidates[/dim])")
    suffix = " …" if len(subs) > 12 else ""
    lines.append(f"[bold cyan]Hosts:[/bold cyan] {', '.join(subs[:12])}{suffix}")
    con.print(Panel("\n".join(lines), title="[bold green]🛰 PASSIVE SUBDOMAIN ENUM[/bold green]",
                    border_style="green", padding=(0, 2), width=_pw(con)))


def _takeover_panel(con, results):
    vuln = [r for r in results if r["result_type"] == "takeover_vulnerable"]
    cand = [r for r in results if r["result_type"] == "takeover_candidate"]
    if not vuln and not cand:
        return
    lines = []
    for r in vuln:
        d = r["data"]
        lines.append(f"[bold red]⚠ VULNERABLE:[/bold red] {d['subdomain']} "
                     f"→ {d['cname']}  [dim]({d['service']})[/dim]")
        lines.append(f"   [dim]{d['reason']}[/dim]")
    for r in cand:
        d = r["data"]
        lines.append(f"[yellow]○ candidate:[/yellow] {d['subdomain']} "
                     f"→ {d['cname']}  [dim]({d['service']})[/dim]")
    border = "red" if vuln else "yellow"
    con.print(Panel("\n".join(lines),
                    title="[bold red]⌖ SUBDOMAIN TAKEOVER[/bold red]",
                    border_style=border, padding=(0, 2), width=_pw(con)))


def _js_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "js_mine_summary"), None)
    secrets = [r for r in results if r["result_type"] == "js_secret"]
    endpoints = [r for r in results if r["result_type"] == "js_endpoint"]
    if not summary and not secrets:
        return
    lines = []
    if summary:
        d = summary["data"]
        lines.append(f"[bold cyan]Scripts analyzed:[/bold cyan] {d.get('scripts_analyzed', 0)}"
                     f"  ·  endpoints: {d.get('endpoints_found', 0)}"
                     f"  ·  secrets: {d.get('secrets_found', 0)}")
    for r in secrets:
        d = r["data"]
        col = "bold red" if d["severity"] in ("critical", "high") else "yellow"
        lines.append(f"[{col}]⚠ {d['kind']}[/{col}]  [dim]{d['preview']}[/dim]  "
                     f"[dim]{d['script']}[/dim]")
    if endpoints:
        sample = ', '.join(e["data"]["endpoint"] for e in endpoints[:6])
        suffix = " …" if len(endpoints) > 6 else ""
        lines.append(f"[bold cyan]Endpoints:[/bold cyan] {sample}{suffix}")
    border = "red" if any(r["data"]["severity"] in ("critical", "high") for r in secrets) else "green"
    con.print(Panel("\n".join(lines), title="[bold green]⟨/⟩ JS SECRET & ENDPOINT MINING[/bold green]",
                    border_style=border, padding=(0, 2), width=_pw(con)))


def _archive_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "archive_summary"), None)
    interesting = [r for r in results if r["result_type"] == "archive_url"]
    if not summary and not interesting:
        return
    lines = []
    if summary:
        d = summary["data"]
        lines.append(f"[bold cyan]Historical URLs:[/bold cyan] {d.get('total_urls', 0)}"
                     f"  ·  interesting: {d.get('interesting_urls', 0)}"
                     f"  ·  hist. subdomains: {d.get('historical_subdomains', 0)}"
                     f"  ·  params: {d.get('param_count', 0)}")
        src = d.get("sources", {})
        if src:
            lines.append(f"[bold cyan]Sources:[/bold cyan] "
                         + "  ".join(f"{k}:{v}" for k, v in src.items()))
    sens = [r for r in interesting if "sensitive-file" in r["data"].get("flags", [])]
    for r in sens[:8]:
        lines.append(f"[bold red]⚠ sensitive file:[/bold red] {r['data']['url']}")
    other = [r for r in interesting if "sensitive-file" not in r["data"].get("flags", [])]
    if other:
        lines.append(f"[dim]+ {len(other)} other flagged endpoint(s) (paths/params)[/dim]")
    border = "red" if sens else "green"
    con.print(Panel("\n".join(lines), title="[bold green]⟲ ARCHIVE URL MINING[/bold green]",
                    border_style=border, padding=(0, 2), width=_pw(con)))


def _infra_panel(con, results):
    fav = next((r for r in results if r["result_type"] == "favicon_hash"), None)
    cert = next((r for r in results if r["result_type"] == "tls_cert_fingerprint"), None)
    jarm = next((r for r in results if r["result_type"] == "jarm_fingerprint"), None)
    sibs = [r for r in results if r["result_type"] == "infra_sibling"]
    if not fav and not cert and not jarm:
        return
    lines = []
    if fav:
        lines.append(f"[bold cyan]Favicon hash:[/bold cyan] {fav['data']['value']}  "
                     f"[dim]{fav['data']['shodan_dork']}[/dim]")
    if jarm:
        lines.append(f"[bold cyan]JARM:[/bold cyan] {jarm['data']['value']}")
    if cert:
        d = cert["data"]
        lines.append(f"[bold cyan]TLS cert:[/bold cyan] {d['value'][:32]}…  "
                     f"[dim]CN={d.get('subject_cn')} · issuer={d.get('issuer')} · "
                     f"{d.get('san_count', 0)} SANs[/dim]")
    if sibs:
        by_kind = {}
        for r in sibs:
            by_kind.setdefault(r["data"]["pivot_kind"], []).append(r["data"]["ip"])
        for kind, ips in by_kind.items():
            lines.append(f"[bold green]Siblings ({kind}):[/bold green] {len(ips)} host(s) — "
                         f"{', '.join(ips[:6])}{' …' if len(ips) > 6 else ''}")
    con.print(Panel("\n".join(lines), title="[bold green]◎ INFRA PIVOT (favicon + TLS)[/bold green]",
                    border_style="green", padding=(0, 2), width=_pw(con)))


def _service_panel(con, results):
    users = next((r for r in results if r["result_type"] == "smtp_users"), None)
    relay = next((r for r in results if r["result_type"] == "smtp_open_relay"), None)
    snmp = [r for r in results if r["result_type"] == "snmp_community"]
    if not users and not relay and not snmp:
        return
    lines = []
    if users:
        d = users["data"]
        lines.append(f"[bold red]⚠ SMTP users ({d['method']}):[/bold red] "
                     f"{', '.join(d['valid_users'][:15])}")
    if relay:
        lines.append("[bold red]⚠ SMTP OPEN RELAY[/bold red] — "
                     f"{relay['data']['detail']}")
    for r in snmp:
        d = r["data"]
        lines.append(f"[bold red]⚠ SNMP community '{d['community']}':[/bold red] "
                     f"[dim]{d['sys_descr'][:80]}[/dim]")
    con.print(Panel("\n".join(lines), title="[bold red]⌗ SERVICE ENUMERATION[/bold red]",
                    border_style="red", padding=(0, 2), width=_pw(con)))


def _docmeta_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "doc_metadata_summary"), None)
    users   = next((r for r in results if r["result_type"] == "metadata_usernames"), None)
    software = next((r for r in results if r["result_type"] == "metadata_software"), None)
    paths   = next((r for r in results if r["result_type"] == "metadata_paths"), None)
    emails  = next((r for r in results if r["result_type"] == "metadata_emails"), None)
    geo     = [r for r in results if r["result_type"] == "document_geolocation"]
    if not summary:
        return

    s = summary["data"]
    lines = [f"[dim]{s['documents_parsed']} document(s) parsed "
             f"of {s['candidates']} candidate(s)[/dim]"]
    if users:
        lines.append(f"[bold red]⚠ Usernames ({users['data']['count']}):[/bold red] "
                     f"{', '.join(users['data']['usernames'][:15])}")
    if paths:
        lines.append(f"[bold red]⚠ Internal paths ({paths['data']['count']}):[/bold red] "
                     f"[dim]{'; '.join(paths['data']['paths'][:5])}[/dim]")
    if emails:
        lines.append(f"[bold yellow]Emails ({emails['data']['count']}):[/bold yellow] "
                     f"{', '.join(emails['data']['emails'][:15])}")
    if software:
        lines.append(f"[bold cyan]Software ({software['data']['count']}):[/bold cyan] "
                     f"[dim]{', '.join(software['data']['software'][:10])}[/dim]")
    for g in geo:
        d = g["data"]
        lines.append(f"[bold red]⚠ Geotag:[/bold red] {d['lat']}, {d['lon']} "
                     f"[dim]({d['url']})[/dim]")

    con.print(Panel("\n".join(lines), title="[bold green]◈ DOCUMENT METADATA[/bold green]",
                    border_style="green", padding=(0, 2), width=_pw(con)))


def _username_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "username_enum_summary"), None)
    accounts = [r for r in results if r["result_type"] == "username_account"]
    if not summary:
        return

    s = summary["data"]
    lines = [f"[dim]handle '[white]{s['username']}[/white]' — "
             f"{s['accounts_found']} account(s) across {s['sites_checked']} sites checked[/dim]"]
    by_cat = s.get("by_category", {})
    if by_cat:
        cats = ", ".join(f"{k}: {v}" for k, v in sorted(by_cat.items(), key=lambda x: -x[1]))
        lines.append(f"[dim]by category:[/dim] {cats}")
    for r in sorted(accounts, key=lambda x: x["data"]["site"].lower())[:40]:
        d = r["data"]
        lines.append(f"[cyan]{d['site']}[/cyan] [dim]({d['category']})[/dim] {d['url']}")
    if len(accounts) > 40:
        lines.append(f"[dim]… and {len(accounts) - 40} more[/dim]")

    con.print(Panel("\n".join(lines), title="[bold green]◈ USERNAME ENUMERATION[/bold green]",
                    border_style="green", padding=(0, 2), width=_pw(con)))


def _profile_pivot_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "profile_pivot_summary"), None)
    linked = [r for r in results if r["result_type"] == "linked_identity"]
    if not summary:
        return

    s = summary["data"]
    lines = [f"[dim]seed '[white]{s['seed']}[/white]' — parsed {s['profiles_parsed']} profile(s) → "
             f"{s['linked_handles']} handle(s), {s['linked_emails']} email(s), "
             f"{s['linked_domains']} domain(s)[/dim]"]
    for r in sorted(linked, key=lambda x: (-x["data"].get("link_count", 0),
                                           x["data"]["kind"]))[:30]:
        d = r["data"]
        mult = f" [dim]×{d['link_count']}[/dim]" if d.get("link_count", 0) >= 2 else ""
        if d["kind"] == "handle":
            lines.append(f"[cyan]{d['platform']}[/cyan]: {d['value']}{mult}")
        elif d["kind"] == "email":
            lines.append(f"[bold yellow]email:[/bold yellow] {d['value']}{mult}")
        elif d["kind"] == "domain":
            lines.append(f"[green]domain:[/green] {d['value']}{mult}")
        elif d["kind"] == "gravatar_md5":
            lines.append(f"[dim]gravatar md5:[/dim] {d['value']}")

    con.print(Panel("\n".join(lines), title="[bold green]◈ PROFILE PIVOT[/bold green]",
                    border_style="green", padding=(0, 2), width=_pw(con)))


def _darkweb_panel(con, results):
    summary = next((r for r in results if r["result_type"] == "darkweb_summary"), None)
    hits = [r for r in results if r["result_type"] == "ransomware_exposure"]
    creds = [r for r in results if r["result_type"] == "credential_exposure"]
    tor_na = next((r for r in results if r["result_type"] == "tor_unavailable"), None)
    if not summary:
        return

    s = summary["data"]
    if not hits and not creds:
        con.print(f"  [dim]◈ Dark web: no leak-site or credential exposure found for "
                  f"{s['target']} ({', '.join(s['sources_checked'])})[/dim]\n")
        return

    lines = []
    if hits:
        lines.append(f"[bold red]⚠ {s['ransomware_hits']} ransomware leak-site "
                     f"exposure(s)[/bold red] for [white]{s['target']}[/white]")
        for r in sorted(hits, key=lambda x: x["data"].get("discovered", ""), reverse=True):
            d = r["data"]
            stealer = " [red](+ infostealer data)[/red]" if d.get("has_infostealer_data") else ""
            conf = "confirmed" if d.get("match") == "domain" else "name-match"
            lines.append(f"[red]{d['group']}[/red] — {d['victim']} [dim]({d['attack_date'][:10]}, "
                         f"{conf})[/dim]{stealer}")
            if d.get("claim_url"):
                lines.append(f"  [dim]{d['claim_url']}[/dim]")
    if creds:
        lines.append(f"[bold red]⚠ {len(creds)} credential exposure(s)[/bold red] "
                     f"[dim](passwords masked)[/dim]")
        for r in creds[:15]:
            d = r["data"]
            where = f" @ {d['host']}" if d.get("kind") == "service_credential" else ""
            lines.append(f"[red]{d['identity']}[/red]{where} → {d['password']} "
                         f"[dim]({d['dump']})[/dim]")
    if tor_na:
        lines.append(f"[dim]Tor: {tor_na['data']['reason']}[/dim]")

    con.print(Panel("\n".join(lines), title="[bold red]⌗ DARK WEB EXPOSURE[/bold red]",
                    border_style="red", padding=(0, 2), width=_pw(con)))


def _port_panel(con, results):
    open_ports = [r for r in results if r["result_type"] == "open_port"]
    summary_r  = next((r for r in results if r["result_type"] == "port_scan_summary"), None)
    os_r       = next((r for r in results if r["result_type"] == "os_detection"),      None)
    passive_r  = next((r for r in results if r["result_type"] == "passive_os"),        None)
    stealth_r  = next((r for r in results if r["result_type"] == "stealth_unavailable"), None)

    if not open_ports:
        if stealth_r:
            d = stealth_r["data"]
            con.print(f"  [yellow]⚠ {d['profile']} scan unavailable:[/yellow] {d['reason']}\n")
        return

    t = Table(show_header=True, header_style="bold green", box=None,
              pad_edge=False, padding=(0, 1), expand=True)
    t.add_column("PORT",    style="cyan",       width=7,  no_wrap=True)
    t.add_column("SERVICE", style="white",      width=14, no_wrap=True)
    t.add_column("PROTO",   style="dim",        width=5,  no_wrap=True)
    t.add_column("VERSION", style="dim white",  width=34, no_wrap=True)
    t.add_column("BANNER",  style="dim",        ratio=1,  no_wrap=True)
    t.add_column("RISK",                        width=8,  no_wrap=True)

    for r in sorted(open_ports, key=lambda x: x["data"].get("port", 0)):
        d      = r["data"]
        danger = d.get("danger_warning")
        risk   = "[bold red]HIGH[/bold red]" if danger else "[green]LOW[/green]"
        banner = (d.get("banner") or "")[:60].replace("\n", " ").replace("\r", "")
        ver    = (d.get("version") or "")[:34]
        proto  = d.get("protocol", "tcp")
        t.add_row(
            str(d.get("port", "")),
            d.get("service", ""),
            proto,
            ver or "—",
            banner or "—",
            risk,
        )

    footer = f"[bold]{len(open_ports)}[/bold] open port(s)"
    engine = "python async"
    if summary_r:
        dp     = summary_r["data"].get("dangerous_ports", [])
        ra     = summary_r["data"].get("risk_assessment", {})
        engine = summary_r["data"].get("scan_engine", "python")
        if dp:
            ports_str = ", ".join(str(p["port"]) for p in dp[:5])
            footer += f" · [red]{len(dp)} dangerous: {ports_str}[/red]"
        lvl = ra.get("level", "")
        if lvl:
            lvl_color = "red" if lvl in ("CRITICAL", "HIGH") else "yellow"
            footer += f" · Risk: [bold {lvl_color}]{lvl}[/bold {lvl_color}]"

    if engine == "nmap":
        engine_tag = "[dim]nmap -sV -O[/dim]"
    elif engine.startswith("nmap-"):
        engine_tag = f"[dim]nmap {engine.split('-', 1)[1]} scan[/dim]"
    else:
        engine_tag = "[dim]async TCP[/dim]"
    if os_r:
        d       = os_r["data"]
        os_name = d.get("os_name", "Unknown")
        acc     = d.get("accuracy", 0)
        fam     = d.get("os_family", "")
        footer += f" · OS: [cyan]{os_name}[/cyan]" + (f" ({fam})" if fam else "") + f" [{acc}%]"
    elif passive_r:
        d   = passive_r["data"]
        pct = int(d.get("confidence", 0) * 100)
        footer += (f" · OS(passive): [cyan]{d.get('os_family')}[/cyan] "
                   f"[TTL {d.get('initial_ttl')}, {d.get('hop_count')} hops, {pct}%]")

    con.print(Panel(t, title=f"[bold green]◈ PORT SCAN[/bold green]  {engine_tag}",
                    border_style="green", padding=(0, 2), width=_pw(con)))
    con.print(f"  {footer}\n")


def _tech_panel(con, results):
    techs     = [r for r in results if r["result_type"] == "technology"]
    posture_r = next((r for r in results if r["result_type"] == "security_posture"), None)
    tls_r     = next((r for r in results if r["result_type"] == "tls_certificate"),  None)
    headers_r = next((r for r in results if r["result_type"] == "http_headers"),     None)

    lines = []

    if techs:
        parts = []
        for tech in sorted(techs, key=lambda x: x["data"].get("confidence", 0), reverse=True)[:12]:
            d   = tech["data"]
            cat = d.get("category", "")
            ver = d.get("version")
            entry = f"[cyan]{d['name']}[/cyan]" + (f" {ver}" if ver else "")
            if cat:
                entry = f"[dim][{cat}][/dim] {entry}"
            parts.append(entry)
        lines.append("[bold cyan]Stack:[/bold cyan] " + " · ".join(parts))

    if headers_r:
        d     = headers_r["data"]
        parts = []
        if d.get("server_fingerprint"):
            parts.append(f"Server: [cyan]{d['server_fingerprint']}[/cyan]")
        if d.get("powered_by"):
            parts.append(f"X-Powered-By: [cyan]{d['powered_by']}[/cyan]")
        if parts:
            lines.append("[bold cyan]Fingerprint:[/bold cyan] " + " · ".join(parts))

    if posture_r:
        d      = posture_r["data"]
        rating = d.get("rating", "?")
        score  = d.get("score", 0)
        color  = "green" if rating == "A" else "yellow" if rating in ("B", "C") else "red"
        missing = ", ".join(d.get("missing", [])[:4])
        grade_line = (f"[bold cyan]Security Headers:[/bold cyan] "
                      f"[{color}]Grade {rating} ({score}/100)[/{color}]")
        if missing:
            grade_line += f" — missing: [dim]{missing}[/dim]"
        lines.append(grade_line)

    if tls_r:
        d      = tls_r["data"]
        issuer = d.get("issuer", {}).get("organizationName", "?")
        lines.append(f"[bold cyan]TLS:[/bold cyan] {d.get('version','?')} · "
                     f"issuer: [cyan]{issuer}[/cyan] · "
                     f"expires: [dim]{d.get('not_after','?')}[/dim]")

    if lines:
        con.print(Panel("\n".join(lines), title="[bold green]◈ TECH STACK[/bold green]",
                        border_style="green", padding=(0, 2), width=_pw(con)))


def _api_panel(con, results):
    endpoints = [r for r in results if r["result_type"] in ("api_endpoint", "web_resource")]
    if not endpoints:
        return

    sensitive_exposed = [
        r for r in endpoints
        if r["data"].get("is_sensitive") and r["data"].get("is_accessible")
    ]

    t = Table(show_header=True, header_style="bold green", box=None,
              pad_edge=False, padding=(0, 1))
    t.add_column("STATUS", width=7,  no_wrap=True)
    t.add_column("TYPE",   width=18, no_wrap=True)
    t.add_column("PATH",   style="cyan", max_width=50)
    t.add_column("AUTH",   width=7,  no_wrap=True)
    t.add_column("!",      width=3,  no_wrap=True)

    to_show = sorted(
        endpoints,
        key=lambda r: (not r["data"].get("is_sensitive"), r["data"].get("status_code", 0)),
    )[:25]

    for r in to_show:
        d      = r["data"]
        status = d.get("status_code", "?")
        if status == 200:
            sc = f"[green]{status}[/green]"
        elif status in (301, 302, 307, 308):
            sc = f"[yellow]{status}[/yellow]"
        else:
            sc = f"[dim]{status}[/dim]"
        path  = (d.get("path") or d.get("url") or "?")[:50]
        etype = (d.get("endpoint_type") or "")[:18]
        auth  = "[yellow]auth[/yellow]" if d.get("requires_auth") else ""
        flag  = "[bold red]![/bold red]" if d.get("is_sensitive") else ""
        t.add_row(sc, etype, path, auth, flag)

    footer = f"[bold]{len(endpoints)}[/bold] resources probed"
    if sensitive_exposed:
        footer += f" · [bold red]{len(sensitive_exposed)} sensitive & accessible[/bold red]"

    con.print(Panel(t, title="[bold green]◈ EXPOSED RESOURCES[/bold green]",
                    border_style="green", padding=(0, 2), width=_pw(con)))
    con.print(f"  {footer}\n")


def _intel_panel(con, results):
    lines = []

    for r in results:
        if r["result_type"] == "ip_geolocation":
            d         = r["data"]
            loc_parts = [p for p in [d.get("city"), d.get("region"), d.get("country")] if p]
            loc       = ", ".join(loc_parts)
            org       = d.get("org", "")
            flags     = []
            if d.get("is_tor"):   flags.append("[bold red]TOR EXIT NODE[/bold red]")
            if d.get("is_vpn"):   flags.append("[yellow]VPN[/yellow]")
            if d.get("is_proxy"): flags.append("[yellow]PROXY[/yellow]")
            flag_str  = ("  " + " ".join(flags)) if flags else ""
            lines.append(f"[bold cyan]GeoIP:[/bold cyan] {loc} · [cyan]{org}[/cyan]{flag_str}")
            if d.get("asn"):
                lines.append(f"[bold cyan]ASN:[/bold cyan] {d['asn']}")
            if d.get("timezone"):
                lines.append(f"[bold cyan]Timezone:[/bold cyan] {d['timezone']}")

    if lines:
        con.print(Panel("\n".join(lines), title="[bold green]◈ NETWORK INTEL[/bold green]",
                        border_style="green", padding=(0, 2), width=_pw(con)))


def _anomaly_panel(con, anomalies):
    lines = []
    for r in anomalies[:12]:
        module = r.get("module", "?")
        rtype  = r.get("result_type", "?")
        d      = r.get("data", {})
        detail = (
            d.get("danger_warning")
            or d.get("nameserver")
            or d.get("path")
            or d.get("recommendation")
            or d.get("summary")
            or ""
        )
        line = f"[red]▸[/red] [dim][{module}][/dim] [bold white]{rtype}[/bold white]"
        if detail:
            line += f" — [yellow]{str(detail)[:80]}[/yellow]"
        lines.append(line)

    con.print(Panel("\n".join(lines), title="[bold red]⚠  ANOMALIES DETECTED[/bold red]",
                    border_style="red", padding=(0, 2), width=_pw(con)))


def _summary_footer(con, scan_dict, results_list):
    score  = scan_dict.get("shadow_score", 0)
    threat = (scan_dict.get("threat_level") or "unknown").upper()
    s_color = "red"    if score  >= 70                          else "yellow" if score  >= 35 else "green"
    t_color = "red"    if threat in ("CRITICAL", "MALICIOUS")   else "yellow" if threat == "SUSPICIOUS" else "green"

    con.print()
    con.rule("[bold green]◈ SHADOW ANALYSIS[/bold green]", style="green")
    con.print(f"\n  Shadow Score   [bold][{s_color}]{score:.0f} / 100[/{s_color}][/bold]")
    con.print(f"  Threat Level   [bold][{t_color}]{threat}[/{t_color}][/bold]")
    con.print(f"  Data Points    {len(results_list)} results harvested")
    con.print()
    con.print("[dim]  ◦ Extend coverage with API keys: phantomsignal config --list-apis[/dim]")
    con.print("[dim]    shodan · virustotal · abuseipdb · greynoise · censys · securitytrails[/dim]\n")


def _render_scan_results(con, results_list, scan_dict, target):
    from collections import defaultdict
    by_module = defaultdict(list)
    for r in results_list:
        by_module[r["module"]].append(r)

    anomalies = [r for r in results_list if r.get("is_anomaly")]

    con.print()
    con.rule(f"[bold green]◈ GHOST RUN COMPLETE — {target}[/bold green]", style="green")
    con.print()

    if "dns_recon"  in by_module: _dns_panel(con,   by_module["dns_recon"])
    if "subdomain_enum" in by_module: _subdomain_panel(con, by_module["subdomain_enum"])
    if "takeover"   in by_module: _takeover_panel(con, by_module["takeover"])
    if "port_scan"  in by_module: _port_panel(con,  by_module["port_scan"])
    if "tech_detect" in by_module: _tech_panel(con, by_module["tech_detect"])
    if "api_hunt"   in by_module: _api_panel(con,   by_module["api_hunt"])
    if "js_mine"    in by_module: _js_panel(con,    by_module["js_mine"])
    if "archive_mine" in by_module: _archive_panel(con, by_module["archive_mine"])
    if "infra_pivot" in by_module: _infra_panel(con, by_module["infra_pivot"])
    if "service_enum" in by_module: _service_panel(con, by_module["service_enum"])
    if "doc_metadata" in by_module: _docmeta_panel(con, by_module["doc_metadata"])
    if "username_enum" in by_module: _username_panel(con, by_module["username_enum"])
    if "profile_pivot" in by_module: _profile_pivot_panel(con, by_module["profile_pivot"])
    if "darkweb"    in by_module: _darkweb_panel(con, by_module["darkweb"])
    if "intel"      in by_module: _intel_panel(con, by_module["intel"])
    if anomalies:                  _anomaly_panel(con, anomalies)

    _summary_footer(con, scan_dict, results_list)


def print_banner():
    console.print(BANNER, style="bold green")


@click.group()
@click.version_option(__version__, prog_name="phantomsignal")
@click.option("--config", "-c", default=None, help="Path to config file")
@click.pass_context
def main(ctx, config):
    """
    PhantomSignal — Open Source OSINT Intelligence Framework

    \b
    "Map the surface. Own the signal."
    """
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config

    from phantomsignal.core.config import PhantomSignalConfig
    from phantomsignal.core.database import init_db
    if config:
        PhantomSignalConfig(config_path=config)
    init_db()


@main.command()
@click.option("--host", "-H", default=None, help="Bind host (default: 127.0.0.1)")
@click.option("--port", "-p", default=None, type=int, help="Bind port (default: 5000)")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--open-browser", "-b", is_flag=True, help="Auto-open browser")
def web(host, port, debug, open_browser):
    """Launch the PhantomSignal web interface — the Shadow Grid control panel."""
    print_banner()
    console.print(DISCLAIMER, style="bold yellow")

    from phantomsignal.core.config import config as cfg
    _host = host or cfg.get("server", "host", default="127.0.0.1")
    _port = port or cfg.get("server", "port", default=5000)
    _debug = debug or cfg.get("server", "debug", default=False)

    console.print(f"\n[bold green]>> SIGNAL LOCKED[/bold green]")
    console.print(f"   Grid interface: [bold cyan]http://{_host}:{_port}[/bold cyan]")
    console.print(f"   Mode: {'[yellow]DEBUG[/yellow]' if _debug else '[green]STEALTH[/green]'}")
    console.print(f"   [dim]Press Ctrl+C to sever the connection[/dim]\n")

    if open_browser:
        import threading, webbrowser
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{_host}:{_port}")).start()

    from phantomsignal.web.app import create_app, socketio

    app = create_app()
    socketio.run(app, host=_host, port=_port, debug=_debug, use_reloader=False, allow_unsafe_werkzeug=True)


@main.command()
@click.argument("target")
@click.option("--type", "-t", "scan_type",
              type=click.Choice(["web_recon", "ip_recon", "domain_recon", "people_intel", "full_spectrum"]),
              default="web_recon", help="Scan type")
@click.option("--modules", "-m", multiple=True,
              help="Modules to run (dns_recon, subdomain_enum, takeover, port_scan, tech_detect, api_hunt, js_mine, archive_mine, infra_pivot, service_enum, doc_metadata, username_enum, profile_pivot, darkweb, web_crawl, intel)")
@click.option("--profile", "-p",
              type=click.Choice(["quick", "standard", "deep", "ghost"]),
              default="standard")
@click.option("--output", "-o", default=None, help="Output directory (defaults to /tmp)")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "csv", "html", "xml", "pdf", "markdown", "stix"]),
              default="json", help="Output format")
@click.option("--compress", is_flag=True)
@click.option("--encrypt", is_flag=True)
@click.option("--password", default=None, help="Encryption password")
@click.option("--no-robots", is_flag=True, help="Ignore robots.txt")
@click.option("--stealth", type=click.Choice(["decoy", "idle"]), default=None,
              help="Stealth port-scan profile (nmap + root only)")
@click.option("--zombie", default=None,
              help="Zombie host for an idle scan (--stealth idle)")
@click.option("--decoys", default=None,
              help="Decoy spec for a decoy scan, e.g. RND:10 or ip1,ME,ip2 (--stealth decoy)")
def scan(target, scan_type, modules, profile, output, fmt, compress, encrypt,
         password, no_robots, stealth, zombie, decoys):
    """Launch a ghost run against a target from the command line."""
    print_banner()
    console.print(DISCLAIMER, style="yellow")

    console.print(f"\n[bold green]◈ TARGET LOCKED:[/bold green] [bold white]{target}[/bold white]")
    console.print(f"[dim]  Scan type: {scan_type} | Profile: {profile}[/dim]\n")

    if not click.confirm("Confirm you have authorization to scan this target?", default=False):
        console.print("[red]Mission aborted — no authorization confirmed.[/red]")
        sys.exit(1)

    # An idle scan bounces probes off a third-party zombie host — that machine is
    # also implicated in the scan, so require separate authorization for it.
    if stealth == "idle":
        console.print(f"[yellow]  ⚠ Idle scan bounces off zombie host "
                      f"[bold]{zombie or '(not set)'}[/bold] — a third party.[/yellow]")
        if not click.confirm("Confirm you are also authorized to use that zombie host?",
                             default=False):
            console.print("[red]Mission aborted — no zombie authorization confirmed.[/red]")
            sys.exit(1)

    from phantomsignal.core.config import config as cfg
    from phantomsignal.core.database import get_db
    from phantomsignal.core.models import Scan, ScanType, ScanStatus
    from phantomsignal.core.engine import PhantomEngine

    if no_robots:
        cfg.set("scraper", "respect_robots_txt", value=False)

    with get_db() as db:
        scan_obj = Scan(
            name=f"CLI Ghost Run — {target[:30]}",
            target=target,
            scan_type=ScanType(scan_type),
            profile=profile,
            modules_enabled=list(modules) if modules else ["dns_recon", "port_scan", "tech_detect", "api_hunt", "intel"],
            options={"depth": 2 if profile == "quick" else 3,
                     "stealth": stealth, "zombie": zombie, "decoys": decoys},
        )
        db.add(scan_obj)
        db.flush()
        scan_id = scan_obj.id

    engine = PhantomEngine()

    with Progress(
        SpinnerColumn(style="green"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=40, style="green", complete_style="bright_green"),
        TextColumn("[dim]{task.percentage:.0f}%"),
        console=console,
    ) as progress:
        task = progress.add_task("Ghost run in progress...", total=100)

        def _update_progress(p):
            progress.update(task, completed=p)

        async def _run():
            engine._progress_callbacks[scan_id] = [lambda p, _: _update_progress(p)]
            await engine.launch_scan(scan_id)

        asyncio.run(_run())

    with get_db() as db:
        from phantomsignal.core.models import ScanResult
        scan_obj = db.query(Scan).filter(Scan.id == scan_id).first()
        results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
        scan_dict = scan_obj.to_dict()
        results_list = [r.to_dict() for r in results]

    _render_scan_results(console, results_list, scan_dict, target)

    if output:
        from phantomsignal.exporters.manager import ExportManager
        manager = ExportManager(output_dir=output)
        result = manager.export(
            scan_id=scan_id,
            fmt=fmt,
            compress=compress,
            encrypt=encrypt,
            encryption_password=password,
        )
        console.print(f"\n[bold green]✓ Intel packet exported:[/bold green] {result['file_path']}")
        console.print(f"  Size: {result['file_size_human']} | SHA256: {result['checksum_sha256'][:16]}...")


@main.command()
@click.option("--first-name", "-f", default=None)
@click.option("--last-name", "-l", default=None)
@click.option("--email", "-e", default=None)
@click.option("--phone", "-p", default=None)
@click.option("--username", "-u", default=None)
@click.option("--output", "-o", default=None)
def profile(first_name, last_name, email, phone, username, output):
    """Build a shadow profile — aggregate people intelligence from all configured APIs."""
    print_banner()

    if not any([first_name, last_name, email, phone, username]):
        console.print("[red]At least one identifier required.[/red]")
        sys.exit(1)

    from phantomsignal.intel.people.aggregator import ShadowProfileBuilder
    from phantomsignal.core.config import config as cfg

    console.print(f"\n[bold cyan]◉ INITIATING SHADOW PROFILER...[/bold cyan]")

    with console.status("[bold green]Scanning the grid...", spinner="dots"):
        builder = ShadowProfileBuilder(cfg)
        result = asyncio.run(builder.build_profile(
            first_name=first_name,
            last_name=last_name,
            email=email,
            phone=phone,
            username=username,
        ))

    console.print(f"\n[bold green]SHADOW PROFILE COMPILED[/bold green]")
    console.print(f"Confidence: [cyan]{result.get('confidence', 0):.0%}[/cyan]")
    console.print(f"Shadow Score: [{'red' if result.get('shadow_score', 0) > 60 else 'green'}]{result.get('shadow_score', 0):.0f}/100[/]")
    console.print(f"Sources: [cyan]{', '.join(result.get('sources', []))}[/cyan]")

    if result.get("emails"):
        console.print(f"\n[bold]Emails:[/bold]")
        for e in result["emails"][:10]:
            console.print(f"  ● {e.get('value', e)}")

    if result.get("phones"):
        console.print(f"\n[bold]Phones:[/bold]")
        for p in result["phones"][:10]:
            console.print(f"  ● {p.get('value', p)}")

    if result.get("addresses"):
        console.print(f"\n[bold]Addresses:[/bold]")
        for a in result["addresses"][:5]:
            console.print(f"  ● {json.dumps(a, default=str)[:120]}")

    if result.get("breach_data"):
        console.print(f"\n[bold red]⚠ BREACHES DETECTED: {len(result['breach_data'])}[/bold red]")
        for b in result["breach_data"][:5]:
            console.print(f"  ✗ {b.get('name', '?')} ({b.get('breach_date', '?')})")

    if output:
        with open(output, "w") as f:
            json.dump(result, f, indent=2, default=str)
        console.print(f"\n[green]✓ Profile saved: {output}[/green]")


@main.command()
def status():
    """Show the PhantomSignal grid status — configured APIs, recent scans."""
    print_banner()

    from phantomsignal.core.database import get_db
    from phantomsignal.core.models import Scan, ScanStatus
    from phantomsignal.intel.orchestrator import IntelOrchestrator
    from phantomsignal.core.config import config as cfg

    with get_db() as db:
        total = db.query(Scan).count()
        running = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count()
        recent = db.query(Scan).order_by(Scan.created_at.desc()).limit(5).all()

    orch = IntelOrchestrator(cfg)
    apis = orch.get_api_status()
    configured = [a for a in apis if a.get("is_configured")]

    table = Table(title="[bold green]GRID STATUS[/bold green]", show_header=True, header_style="bold green")
    table.add_column("METRIC")
    table.add_column("VALUE", style="cyan")
    table.add_row("Total Scans", str(total))
    table.add_row("Active Ghosts", str(running))
    table.add_row("APIs Online", f"{len(configured)}/{len(apis)}")
    table.add_row("Version", __version__)
    console.print(table)

    api_table = Table(title="[bold cyan]API ARSENAL[/bold cyan]", show_header=True, header_style="bold cyan")
    api_table.add_column("API")
    api_table.add_column("STATUS")
    api_table.add_column("TIER")
    for api in sorted(apis, key=lambda x: (not x.get("is_configured"), x["name"])):
        status_str = "[green]● ONLINE[/green]" if api.get("is_configured") else "[dim]○ OFFLINE[/dim]"
        api_table.add_row(api["name"], status_str, api.get("tier", "?"))
    console.print(api_table)


@main.command()
@click.argument("scan_id")
@click.option("--format", "-f", "fmt", default="json",
              type=click.Choice(["json", "csv", "html", "xml", "pdf", "markdown", "stix"]))
@click.option("--output", "-o", default=None, help="Output directory (defaults to /tmp)")
@click.option("--compress", is_flag=True)
@click.option("--encrypt", is_flag=True)
@click.option("--password", default=None)
def export(scan_id, fmt, output, compress, encrypt, password):
    """Export a ghost run's intel packet to a file."""
    from phantomsignal.exporters.manager import ExportManager
    manager = ExportManager(output_dir=output)
    try:
        result = manager.export(
            scan_id=scan_id,
            fmt=fmt,
            compress=compress,
            encrypt=encrypt,
            encryption_password=password,
        )
        console.print(f"[bold green]✓ Intel packet compiled:[/bold green]")
        console.print(f"  File: {result['file_path']}")
        console.print(f"  Size: {result['file_size_human']}")
        console.print(f"  Results: {result['result_count']}")
        console.print(f"  SHA256: {result['checksum_sha256']}")
    except Exception as e:
        console.print(f"[red]Export failed: {e}[/red]")
        sys.exit(1)


@main.command()
def init():
    """Initialize PhantomSignal — create default config and database."""
    print_banner()
    from phantomsignal.core.database import init_db
    init_db()
    console.print("[bold green]✓ Grid initialized.[/bold green]")
    console.print("  Config: ~/.phantomsignal/config.yaml")
    console.print("  Database: phantomsignal.db")
    console.print("\n[cyan]Next:[/cyan] Add API keys with: [bold]phantomsignal web[/bold] → Settings → Ghost Keys")


if __name__ == "__main__":
    main()
