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
            from phantomsignal.core.http import attribution_scope

            modules = scan.modules_enabled or []
            total_modules = len(modules) or 1
            completed = 0

            pipeline, opsec_map = self._build_pipeline(scan, modules)

            # Every StealthClient request made underneath records into this
            # ledger, so the scan can report its own attribution surface.
            with attribution_scope() as ledger:
                for module_name, module_coro, opsec_level in pipeline:
                    self._log(scan_id, module_name, f"Module online: {module_name.upper()}")
                    self.emit("module_start", {"scan_id": scan_id, "module": module_name}, scan_id)
                    try:
                        results = await asyncio.wait_for(module_coro, timeout=300)
                        await self._store_results(scan_id, module_name, results, opsec_level)
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

            await self._finalize_scan(scan_id, ledger, opsec_map)

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
        """Assemble the module pipeline for a given scan.

        Returns ``(pipeline, opsec_map)`` where ``pipeline`` is a list of
        ``(module_name, coroutine, opsec_level)`` and ``opsec_map`` maps each
        module that will run to its ``OpsecLevel`` value (for the attribution
        report). Modules are resolved from the scraper registry, so new modules
        join the pipeline by registering rather than by editing the engine.
        """
        from phantomsignal.scrapers.registry import get_registered_modules

        registry = get_registered_modules()
        target = scan.target
        # Pass scan_type through options so registry factories keep a uniform
        # (config, target, opts) signature.
        opts = {**(scan.options or {}), "_scan_type": scan.scan_type.value}

        # Default full-spectrum if no modules specified.
        if not modules:
            modules = list(registry.keys())

        pipeline = []
        opsec_map: Dict[str, str] = {}
        for mod in modules:
            spec = registry.get(mod)
            if spec:
                pipeline.append((mod, spec.factory(config, target, opts), spec.opsec.value))
                opsec_map[mod] = spec.opsec.value

        return pipeline, opsec_map

    async def _store_results(
        self, scan_id: str, module: str, results: Optional[List[Dict]],
        opsec_level: Optional[str] = None,
    ) -> None:
        if not results:
            return
        with get_db() as db:
            for item in results:
                data = item.get("data", item)
                # Stamp the module's OPSEC posture onto the finding so the UI and
                # exports can show how attributable the traffic that found it was.
                if opsec_level and isinstance(data, dict) and "opsec" not in data:
                    data = {**data, "opsec": opsec_level}
                result = ScanResult(
                    scan_id=scan_id,
                    module=module,
                    result_type=item.get("type", "unknown"),
                    source=item.get("source"),
                    data=data,
                    confidence=item.get("confidence", 1.0),
                    relevance_score=item.get("relevance_score", 0.5),
                    tags=item.get("tags", []),
                    is_anomaly=item.get("is_anomaly", False),
                )
                db.add(result)

    async def _finalize_scan(self, scan_id: str, ledger=None, opsec_map=None) -> None:
        """Wrap up the scan, compute the risk score, notify clients."""
        # Record the operator's attribution surface for this run — the OPSEC
        # flagship's headline artifact. Best-effort; never fails the scan.
        if ledger is not None:
            try:
                from phantomsignal.intel.opsec import build_attribution_result

                attribution = build_attribution_result(ledger.summary(), opsec_map or {})
                await self._store_results(scan_id, "opsec", [attribution])
                self._log(scan_id, "opsec",
                          f"Attribution surface: {attribution['data']['grade']} — "
                          f"{attribution['data']['proxied_pct']}% proxied across "
                          f"{attribution['data']['total_requests']} request(s)")
                self.emit("attribution_surface",
                          {"scan_id": scan_id, **attribution["data"]}, scan_id)
            except Exception:
                logger.exception(f"Attribution surface failed for scan {scan_id}")

        with get_db() as db:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return
            target = scan.target
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

        # Phase 5b — continuous monitoring: diff this scan against the prior
        # baseline and alert on new sensitive assets. Best-effort; never fails
        # the scan.
        await self._auto_diff(scan_id, target)

    async def _auto_diff(self, scan_id: str, target: str) -> None:
        """
        Auto-diff a just-completed scan against the previous completed scan of
        the same target. Stores the change findings against this scan, emits a
        diff summary to the grid, and pushes a webhook alert when new sensitive
        assets appear.
        """
        try:
            from phantomsignal.intel.asm_diff import ASMDiffer
            from phantomsignal.intel import asm_alert

            findings = ASMDiffer(config).diff_target(target)
            if not findings:
                # First completed scan of this target — no baseline to diff yet.
                return

            await self._store_results(scan_id, "asm_diff", findings)

            summary = asm_alert.diff_summary(findings)
            new = summary.get("new_assets", 0)
            changed = summary.get("changed_assets", 0)
            removed = summary.get("removed_assets", 0)
            new_sensitive = summary.get("new_sensitive", 0)

            self._log(scan_id, "asm_diff",
                      f"ASM diff vs baseline: {new} new · {changed} changed · "
                      f"{removed} removed")
            self.emit("asm_diff_complete", {"scan_id": scan_id, **summary}, scan_id)

            if new_sensitive:
                self._log(scan_id, "asm_diff",
                          f"⚠ {new_sensitive} new sensitive asset(s) since last scan",
                          level="warning")
                self.emit("asm_alert", {
                    "scan_id": scan_id,
                    "target": target,
                    "new_sensitive": new_sensitive,
                }, scan_id)

                webhook = config.get("notifications", "webhook_url")
                if webhook:
                    payload = asm_alert.build_alert_payload(target, findings)
                    ok = await asm_alert.send_alert(webhook, payload)
                    self._log(scan_id, "asm_diff",
                              f"Webhook alert {'delivered' if ok else 'failed'}",
                              level="info" if ok else "warning")
        except Exception as e:
            logger.exception(f"Auto-diff failed for scan {scan_id}")
            self._log(scan_id, "asm_diff", f"Auto-diff error: {e}", level="warning")

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
            # OPSEC telemetry is about the operator, not the target — no weight.
            if result_type == "attribution_surface":
                continue
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
        """Abort a running scan."""
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
