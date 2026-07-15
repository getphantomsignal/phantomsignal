"""
PhantomSignal — Scraper module registry.

Mirrors the Intel-API plugin registry (``intel/apis/base.py``) for recon
modules. Before this, the engine carried a hard-coded ``module_factories`` dict
with inconsistent entrypoints; centralising registration here lets new modules
(external-tool adapters, cloud enum, third-party plugins) join the pipeline
without editing the engine, and lets every module declare its ``OpsecLevel`` so
the attribution-surface report can grade a scan's footprint honestly.

Factories are lazy: the heavy scraper import happens only when a module actually
runs, preserving the engine's original deferred-import behaviour.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Awaitable, Callable, Dict, List

from phantomsignal.intel.opsec import OpsecLevel

# A factory takes (config, target, options) and returns the module's coroutine
# (an awaitable yielding a list of result dicts).
ModuleFactory = Callable[[object, str, Dict], Awaitable]


@dataclass(frozen=True)
class ModuleSpec:
    name: str
    factory: ModuleFactory
    opsec: OpsecLevel
    label: str = ""


_REGISTRY: Dict[str, ModuleSpec] = {}


def register_module(name: str, *, opsec: OpsecLevel, label: str = "") -> Callable[[ModuleFactory], ModuleFactory]:
    """Decorator/registrar for a recon module."""
    def _wrap(factory: ModuleFactory) -> ModuleFactory:
        _REGISTRY[name] = ModuleSpec(name=name, factory=factory, opsec=opsec, label=label or name)
        return factory
    return _wrap


def get_registered_modules() -> Dict[str, ModuleSpec]:
    return dict(_REGISTRY)


def module_names() -> List[str]:
    return list(_REGISTRY.keys())


# ── Built-in module registrations ─────────────────────────────────────────────
# Each factory imports its scraper lazily and invokes the class's entrypoint,
# exactly as the engine did before. OpsecLevel is assigned by whether the module
# actually routes target-facing traffic through StealthClient (verified per
# module) — deliberately conservative so the attribution report never overclaims.

@register_module("dns_recon", opsec=OpsecLevel.ATTRIBUTABLE, label="DNS Recon")
def _dns_recon(config, target, opts):
    from phantomsignal.scrapers.dns_recon import DNSRecon
    return DNSRecon(config).run(target)


@register_module("subdomain_enum", opsec=OpsecLevel.ATTRIBUTABLE, label="Subdomain Enum")
def _subdomain_enum(config, target, opts):
    from phantomsignal.scrapers.subdomain_enum import SubdomainEnumerator
    return SubdomainEnumerator(config).run(target)


@register_module("takeover", opsec=OpsecLevel.STEALTH_GUARANTEED, label="Takeover Detection")
def _takeover(config, target, opts):
    from phantomsignal.scrapers.takeover import TakeoverDetector
    return TakeoverDetector(config).run(target)


@register_module("js_mine", opsec=OpsecLevel.STEALTH_GUARANTEED, label="JS Secret Mining")
def _js_mine(config, target, opts):
    from phantomsignal.scrapers.js_miner import JSMiner
    return JSMiner(config).run(target)


@register_module("archive_mine", opsec=OpsecLevel.ATTRIBUTABLE, label="Archive URL Mining")
def _archive_mine(config, target, opts):
    from phantomsignal.scrapers.archive_miner import ArchiveURLMiner
    return ArchiveURLMiner(config).run(target)


@register_module("infra_pivot", opsec=OpsecLevel.STEALTH_GUARANTEED, label="Infra Pivot")
def _infra_pivot(config, target, opts):
    from phantomsignal.scrapers.infra_pivot import InfraPivot
    return InfraPivot(config).run(target)


@register_module("origin_pivot", opsec=OpsecLevel.STEALTH_GUARANTEED, label="Origin Pivot")
def _origin_pivot(config, target, opts):
    from phantomsignal.scrapers.origin_pivot import OriginPivot
    return OriginPivot(config).run(target)


@register_module("service_enum", opsec=OpsecLevel.ATTRIBUTABLE, label="Service Enum")
def _service_enum(config, target, opts):
    from phantomsignal.scrapers.service_enum import ServiceEnumerator
    return ServiceEnumerator(config).run(target)


@register_module("doc_metadata", opsec=OpsecLevel.ATTRIBUTABLE, label="Document Metadata")
def _doc_metadata(config, target, opts):
    from phantomsignal.scrapers.doc_metadata import DocMetadataExtractor
    return DocMetadataExtractor(config).run(target)


@register_module("username_enum", opsec=OpsecLevel.ATTRIBUTABLE, label="Username Enum")
def _username_enum(config, target, opts):
    from phantomsignal.scrapers.username_enum import UsernameEnumerator
    return UsernameEnumerator(config).run(target)


@register_module("profile_pivot", opsec=OpsecLevel.ATTRIBUTABLE, label="Profile Pivot")
def _profile_pivot(config, target, opts):
    from phantomsignal.intel.people.profile_pivot import ProfilePivotEngine
    return ProfilePivotEngine(config).run(target)


@register_module("darkweb", opsec=OpsecLevel.PROXIED, label="Dark Web Monitor")
def _darkweb(config, target, opts):
    from phantomsignal.scrapers.darkweb import DarkWebMonitor
    return DarkWebMonitor(config).run(target)


@register_module("email_oracle", opsec=OpsecLevel.ATTRIBUTABLE, label="Email Oracle")
def _email_oracle(config, target, opts):
    from phantomsignal.scrapers.email_oracle import EmailOracle
    return EmailOracle(config).run(target)


@register_module("port_scan", opsec=OpsecLevel.ATTRIBUTABLE, label="Port Scan")
def _port_scan(config, target, opts):
    from phantomsignal.scrapers.port_scanner import PortScanner
    return PortScanner(config).scan(
        target, opts.get("ports"),
        stealth=opts.get("stealth"),
        decoys=opts.get("decoys"),
        zombie=opts.get("zombie"),
    )


@register_module("tech_detect", opsec=OpsecLevel.STEALTH_GUARANTEED, label="Tech Detection")
def _tech_detect(config, target, opts):
    from phantomsignal.scrapers.tech_detector import TechDetector
    return TechDetector(config).detect(target)


@register_module("api_hunt", opsec=OpsecLevel.STEALTH_GUARANTEED, label="API Hunter")
def _api_hunt(config, target, opts):
    from phantomsignal.scrapers.api_hunter import APIHunter
    return APIHunter(config).hunt(target)


@register_module("web_crawl", opsec=OpsecLevel.STEALTH_GUARANTEED, label="Web Crawl")
def _web_crawl(config, target, opts):
    from phantomsignal.scrapers.crawler import WebCrawler
    return WebCrawler(config).crawl(target, depth=opts.get("depth", 2))


@register_module("intel", opsec=OpsecLevel.ATTRIBUTABLE, label="Intel APIs")
def _intel(config, target, opts):
    from phantomsignal.intel.orchestrator import IntelOrchestrator
    return IntelOrchestrator(config).run(target, opts.get("_scan_type", ""), opts)
