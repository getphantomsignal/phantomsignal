"""
PhantomSignal Core Engine — The Phantom Orchestrator
Coordinates all recon modules and feeds signal to the grid.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from phantomsignal.core.config import config
from phantomsignal.core.database import get_db
from phantomsignal.core.models import Scan, ScanResult, ScanStatus, ThreatLevel

logger = logging.getLogger("phantomsignal.engine")


class PhantomEngine:
    """
    The PhantomSignal core orchestration engine.
    Coordinates scrapers, intel APIs, and data aggregation
    into a unified ghost run pipeline.
    """

    def __init__(self, socketio=None):
        self._socketio = socketio
        self._active_scans: Dict[str, asyncio.Task] = {}
        self._progress_callbacks: Dict[str, List[Callable]] = {}

    def emit(self, event: str, data: Any, scan_id: Optional[str] = None) -> None:
        """Broadcast signal to the web grid via SocketIO."""
        if self._socketio:
            room = f"scan_{scan_id}" if scan_id else None
            self._socketio.emit(event, data, room=room)

    async def launch_scan(self, scan_id: str) -> None:
        """
        Launch a ghost run. Entry point for all scan types.
        Spins up the appropriate module pipeline based on scan configuration.
        """
        from phantomsignal.scrapers.crawler import WebCrawler
        from phantomsignal.scrapers.port_scanner import PortScanner
        from phantomsignal.scrapers.tech_detector import TechDetector
        from phantomsignal.scrapers.api_hunter import APIHunter
        from phantomsignal.scrapers.dns_recon import DNSRecon
        from phantomsignal.intel.orchestrator import IntelOrchestrator

        with get_db() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                logger.error(f"Ghost run {scan_id} not found in grid.")
                return

            scan.status = ScanStatus.RUNNING
            scan.started_at = datetime.utcnow()
            scan.progress = 0
            db.commit()

        self.emit("scan_started", {"scan_id": scan_id, "target": scan.target}, scan_id)
        self._log(scan_id, "system", f"Ghost run initiated. Target: {scan.target}")

        # Give the browser ~1 s to load results.html, connect the WebSocket,
        # and emit join_scan — so no early events are lost to a race condition.
        await asyncio.sleep(1.0)

        try:
            modules = scan.modules_enabled or []
            total_modules = len(modules) or 1
            completed = 0

            pipeline = self._build_pipeline(scan, modules)

            for module_name, module_coro in pipeline:
                self._log(scan_id, module_name, f"Module online: {module_name.upper()}")
                self.emit("module_start", {"scan_id": scan_id, "module": module_name}, scan_id)
                try:
                    results = await asyncio.wait_for(module_coro, timeout=300)
                    await self._store_results(scan_id, module_name, results)
                    completed += 1
                    progress = int((completed / total_modules) * 100)
                    self._update_progress(scan_id, progress)
                    self.emit("module_complete", {
                        "scan_id": scan_id,
                        "module": module_name,
                        "result_count": len(results) if results else 0,
                        "progress": progress,
                    }, scan_id)
                except asyncio.TimeoutError:
                    self._log(scan_id, module_name, f"Module timeout: {module_name} — signal lost", level="warning")
                except Exception as e:
                    self._log(scan_id, module_name, f"Module error [{module_name}]: {e}", level="error")
                    logger.exception(f"Module {module_name} failed for scan {scan_id}")

            await self._finalize_scan(scan_id)

        except Exception as e:
            logger.exception(f"Ghost run {scan_id} critically failed")
            with get_db() as db:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.FAILED
                    scan.error_message = str(e)
                    scan.completed_at = datetime.utcnow()
            self.emit("scan_failed", {"scan_id": scan_id, "error": str(e)}, scan_id)

    def _build_pipeline(self, scan: Scan, modules: List[str]):
        """Assemble the module pipeline for a given scan."""
        from phantomsignal.scrapers.crawler import WebCrawler
        from phantomsignal.scrapers.port_scanner import PortScanner
        from phantomsignal.scrapers.tech_detector import TechDetector
        from phantomsignal.scrapers.api_hunter import APIHunter
        from phantomsignal.scrapers.dns_recon import DNSRecon
        from phantomsignal.scrapers.subdomain_enum import SubdomainEnumerator
        from phantomsignal.scrapers.takeover import TakeoverDetector
        from phantomsignal.scrapers.js_miner import JSMiner
        from phantomsignal.intel.orchestrator import IntelOrchestrator

        pipeline = []
        target = scan.target
        opts = scan.options or {}

        module_factories = {
            "dns_recon": lambda: ("dns_recon", DNSRecon(config).run(target)),
            "subdomain_enum": lambda: ("subdomain_enum", SubdomainEnumerator(config).run(target)),
            "takeover": lambda: ("takeover", TakeoverDetector(config).run(target)),
            "js_mine": lambda: ("js_mine", JSMiner(config).run(target)),
            "port_scan": lambda: ("port_scan", PortScanner(config).scan(target, opts.get("ports"))),
            "tech_detect": lambda: ("tech_detect", TechDetector(config).detect(target)),
            "api_hunt": lambda: ("api_hunt", APIHunter(config).hunt(target)),
            "web_crawl": lambda: ("web_crawl", WebCrawler(config).crawl(target, depth=opts.get("depth", 2))),
            "intel": lambda: ("intel", IntelOrchestrator(config).run(target, scan.scan_type.value, opts)),
        }

        # Default full-spectrum if no modules specified
        if not modules:
            modules = list(module_factories.keys())

        for mod in modules:
            if mod in module_factories:
                pipeline.append(module_factories[mod]())

        return pipeline

    async def _store_results(
        self, scan_id: str, module: str, results: Optional[List[Dict]]
    ) -> None:
        if not results:
            return
        with get_db() as db:
            for item in results:
                result = ScanResult(
                    scan_id=scan_id,
                    module=module,
                    result_type=item.get("type", "unknown"),
                    source=item.get("source"),
                    data=item.get("data", item),
                    confidence=item.get("confidence", 1.0),
                    relevance_score=item.get("relevance_score", 0.5),
                    tags=item.get("tags", []),
                    is_anomaly=item.get("is_anomaly", False),
                )
                db.add(result)

    async def _finalize_scan(self, scan_id: str) -> None:
        """Wrap up the ghost run, compute shadow score, notify grid."""
        with get_db() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return
            results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
            shadow_score = self._compute_shadow_score(results)
            threat_level = self._classify_threat(shadow_score, results)

            scan.status = ScanStatus.COMPLETE
            scan.completed_at = datetime.utcnow()
            scan.progress = 100
            scan.shadow_score = shadow_score
            scan.threat_level = threat_level
            if scan.started_at:
                scan.duration_seconds = (
                    scan.completed_at - scan.started_at
                ).total_seconds()

        self._log(scan_id, "system", f"Ghost run complete. Shadow Score: {shadow_score:.1f}/100")
        self.emit("scan_complete", {
            "scan_id": scan_id,
            "shadow_score": shadow_score,
            "threat_level": threat_level.value,
            "result_count": len(results),
        }, scan_id)

    def _compute_shadow_score(self, results: List[ScanResult]) -> float:
        """
        Compute an aggregate Shadow Score (0-100) based on gathered intel.
        Higher = more digital exposure / threat potential.
        """
        if not results:
            return 0.0

        score = 0.0
        weights = {
            "breach_data": 20,
            "open_port": 5,
            "vulnerability": 15,
            "api_endpoint": 3,
            "email": 4,
            "phone": 4,
            "address": 3,
            "social_profile": 2,
            "criminal_record": 25,
            "dark_web_mention": 30,
            "malicious_indicator": 35,
        }

        for result in results:
            result_type = result.result_type.lower()
            for key, weight in weights.items():
                if key in result_type:
                    score += weight * result.confidence
                    break
            else:
                score += 0.5 * result.confidence

        return min(round(score, 2), 100.0)

    def _classify_threat(self, score: float, results: List[ScanResult]) -> ThreatLevel:
        malicious_types = {"malicious_indicator", "dark_web_mention", "criminal_record"}
        for r in results:
            if r.result_type.lower() in malicious_types:
                return ThreatLevel.MALICIOUS if score < 80 else ThreatLevel.CRITICAL

        if score >= 80:
            return ThreatLevel.CRITICAL
        elif score >= 60:
            return ThreatLevel.MALICIOUS
        elif score >= 35:
            return ThreatLevel.SUSPICIOUS
        elif score > 0:
            return ThreatLevel.CLEAN
        return ThreatLevel.UNKNOWN

    def _update_progress(self, scan_id: str, progress: int) -> None:
        with get_db() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if scan:
                scan.progress = progress

    def _log(
        self, scan_id: str, module: str, message: str, level: str = "info"
    ) -> None:
        """Emit a terminal log event to the live feed."""
        log_entry = {
            "scan_id": scan_id,
            "module": module,
            "message": message,
            "level": level,
            "timestamp": datetime.utcnow().isoformat(),
        }
        self.emit("terminal_log", log_entry, scan_id)
        getattr(logger, level, logger.info)(f"[{scan_id}] [{module}] {message}")

    def abort_scan(self, scan_id: str) -> bool:
        """Send the kill signal — abort a running ghost run."""
        task = self._active_scans.get(scan_id)
        if task and not task.done():
            task.cancel()
            with get_db() as db:
                scan = db.query(Scan).filter(Scan.id == scan_id).first()
                if scan:
                    scan.status = ScanStatus.ABORTED
                    scan.completed_at = datetime.utcnow()
            self.emit("scan_aborted", {"scan_id": scan_id}, scan_id)
            return True
        return False

    def get_active_scans(self) -> List[str]:
        return [sid for sid, task in self._active_scans.items() if not task.done()]


engine = PhantomEngine()
