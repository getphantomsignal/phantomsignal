"""
NightOwl CLI — Ghost Terminal Interface
Operative command-line control for the shadow grid.

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.syntax import Syntax
from rich import print as rprint

from nightowl import __version__, BANNER, DISCLAIMER

console = Console(highlight=True)


def print_banner():
    console.print(BANNER, style="bold green")


@click.group()
@click.version_option(__version__, prog_name="nightowl")
@click.option("--config", "-c", default=None, help="Path to config file")
@click.pass_context
def main(ctx, config):
    """
    🦉 NightOwl — Open Source OSINT Intelligence Framework

    \b
    "See everything. Leave no trace."
    """
    ctx.ensure_object(dict)
    ctx.obj["config_path"] = config

    from nightowl.core.config import NightOwlConfig
    from nightowl.core.database import init_db
    if config:
        NightOwlConfig(config_path=config)
    init_db()


@main.command()
@click.option("--host", "-H", default=None, help="Bind host (default: 127.0.0.1)")
@click.option("--port", "-p", default=None, type=int, help="Bind port (default: 5000)")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--open-browser", "-b", is_flag=True, help="Auto-open browser")
def web(host, port, debug, open_browser):
    """Launch the NightOwl web interface — the Shadow Grid control panel."""
    print_banner()
    console.print(DISCLAIMER, style="bold yellow")

    from nightowl.core.config import config as cfg
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

    from nightowl.web.app import create_app, socketio

    app = create_app()
    socketio.run(app, host=_host, port=_port, debug=_debug, use_reloader=False)


@main.command()
@click.argument("target")
@click.option("--type", "-t", "scan_type",
              type=click.Choice(["web_recon", "ip_recon", "domain_recon", "people_intel", "full_spectrum"]),
              default="web_recon", help="Scan type")
@click.option("--modules", "-m", multiple=True,
              help="Modules to run (dns_recon, port_scan, tech_detect, api_hunt, web_crawl, intel)")
@click.option("--profile", "-p",
              type=click.Choice(["quick", "standard", "deep", "ghost"]),
              default="standard")
@click.option("--output", "-o", default=None, help="Output file path")
@click.option("--format", "-f", "fmt",
              type=click.Choice(["json", "csv", "html", "xml", "pdf", "markdown", "stix"]),
              default="json", help="Output format")
@click.option("--compress", is_flag=True)
@click.option("--encrypt", is_flag=True)
@click.option("--password", default=None, help="Encryption password")
@click.option("--no-robots", is_flag=True, help="Ignore robots.txt")
def scan(target, scan_type, modules, profile, output, fmt, compress, encrypt, password, no_robots):
    """Launch a ghost run against a target from the command line."""
    print_banner()
    console.print(DISCLAIMER, style="yellow")

    console.print(f"\n[bold green]◈ TARGET LOCKED:[/bold green] [bold white]{target}[/bold white]")
    console.print(f"[dim]  Scan type: {scan_type} | Profile: {profile}[/dim]\n")

    if not click.confirm("Confirm you have authorization to scan this target?", default=False):
        console.print("[red]Mission aborted — no authorization confirmed.[/red]")
        sys.exit(1)

    from nightowl.core.config import config as cfg
    from nightowl.core.database import get_db
    from nightowl.core.models import Scan, ScanType, ScanStatus
    from nightowl.core.engine import PhantomEngine

    if no_robots:
        cfg.set("scraper", "respect_robots_txt", value=False)

    with get_db() as db:
        scan_obj = Scan(
            name=f"CLI Ghost Run — {target[:30]}",
            target=target,
            scan_type=ScanType(scan_type),
            profile=profile,
            modules_enabled=list(modules) if modules else ["dns_recon", "port_scan", "tech_detect", "api_hunt", "intel"],
            options={"depth": 2 if profile == "quick" else 3},
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
        from nightowl.core.models import ScanResult
        scan_obj = db.query(Scan).filter(Scan.id == scan_id).first()
        results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
        scan_dict = scan_obj.to_dict()
        results_list = [r.to_dict() for r in results]

    # Display summary
    table = Table(title="[bold green]GHOST RUN RESULTS[/bold green]", show_header=True, header_style="bold green")
    table.add_column("MODULE", style="green")
    table.add_column("TYPE", style="cyan")
    table.add_column("SOURCE")
    table.add_column("CONF", justify="right")

    for r in results_list[:40]:
        table.add_row(
            r.get("module", "—"),
            r.get("result_type", "—"),
            r.get("source", "—"),
            f"{(r.get('confidence', 0) * 100):.0f}%",
        )
    console.print(table)

    console.print(f"\n[bold]Shadow Score:[/bold] [{'red' if scan_dict.get('shadow_score', 0) > 70 else 'green'}]{scan_dict.get('shadow_score', 0):.0f}/100[/]")
    console.print(f"[bold]Threat Level:[/bold] {scan_dict.get('threat_level', 'unknown').upper()}")
    console.print(f"[bold]Results:[/bold] {len(results_list)}")

    if output:
        from nightowl.exporters.manager import ExportManager
        manager = ExportManager(output_dir=str(Path(output).parent))
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

    from nightowl.intel.people.aggregator import ShadowProfileBuilder
    from nightowl.core.config import config as cfg

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
    """Show the NightOwl grid status — configured APIs, recent scans."""
    print_banner()

    from nightowl.core.database import get_db
    from nightowl.core.models import Scan, ScanStatus
    from nightowl.intel.orchestrator import IntelOrchestrator
    from nightowl.core.config import config as cfg

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
@click.option("--output", "-o", default="./exports")
@click.option("--compress", is_flag=True)
@click.option("--encrypt", is_flag=True)
@click.option("--password", default=None)
def export(scan_id, fmt, output, compress, encrypt, password):
    """Export a ghost run's intel packet to a file."""
    from nightowl.exporters.manager import ExportManager
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
    """Initialize NightOwl — create default config and database."""
    print_banner()
    from nightowl.core.database import init_db
    init_db()
    console.print("[bold green]✓ Grid initialized.[/bold green]")
    console.print("  Config: ~/.nightowl/config.yaml")
    console.print("  Database: nightowl.db")
    console.print("\n[cyan]Next:[/cyan] Add API keys with: [bold]nightowl web[/bold] → Settings → Ghost Keys")


if __name__ == "__main__":
    main()
