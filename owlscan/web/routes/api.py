"""OwlScan REST API — Machine-readable grid interface"""
from __future__ import annotations

from flask import Blueprint, jsonify, request
from owlscan.core.database import get_db
from owlscan.core.models import Scan, ScanResult, ScanStatus, ScanType

api_bp = Blueprint("api", __name__)


def _json_ok(data, status=200):
    return jsonify({"status": "ok", "data": data}), status


def _json_err(msg, status=400):
    return jsonify({"status": "error", "message": msg}), status


@api_bp.route("/scans", methods=["GET"])
def list_scans():
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))
    with get_db() as db:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).offset(offset).limit(limit).all()
        total = db.query(Scan).count()
        scans_data = [s.to_dict() for s in scans]
    return _json_ok({"scans": scans_data, "total": total, "limit": limit, "offset": offset})


@api_bp.route("/scans", methods=["POST"])
def create_scan():
    from owlscan.web.app import run_scan_async
    from flask import current_app
    data = request.get_json() or {}
    target = data.get("target", "").strip()
    if not target:
        return _json_err("target is required")

    try:
        scan_type = ScanType(data.get("scan_type", "web_recon"))
    except ValueError:
        scan_type = ScanType.WEB_RECON

    with get_db() as db:
        scan = Scan(
            name=data.get("name", f"API Scan — {target[:30]}"),
            target=target,
            scan_type=scan_type,
            profile=data.get("profile", "standard"),
            modules_enabled=data.get("modules", []),
            options=data.get("options", {}),
            tags=data.get("tags", []),
        )
        db.add(scan)
        db.flush()
        scan_id = scan.id
        scan_dict = scan.to_dict()

    run_scan_async(current_app._get_current_object(), scan_id)
    return _json_ok(scan_dict, 201)


@api_bp.route("/scans/<scan_id>", methods=["GET"])
def get_scan(scan_id):
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return _json_err("Scan not found", 404)
        results = db.query(ScanResult).filter(ScanResult.scan_id == scan_id).all()
        return _json_ok({
            **scan.to_dict(),
            "results": [r.to_dict() for r in results],
        })


@api_bp.route("/scans/<scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return _json_err("Scan not found", 404)
        db.delete(scan)
    return _json_ok({"deleted": scan_id})


@api_bp.route("/scans/<scan_id>/abort", methods=["POST"])
def abort_scan(scan_id):
    from flask import current_app
    current_app.phantom_engine.abort_scan(scan_id)
    return _json_ok({"aborted": scan_id})


@api_bp.route("/apis", methods=["GET"])
def list_apis():
    from owlscan.intel.orchestrator import IntelOrchestrator
    from owlscan.core.config import config
    orch = IntelOrchestrator(config)
    return _json_ok(orch.get_available_apis())


@api_bp.route("/health", methods=["GET"])
def health():
    from owlscan import __version__
    with get_db() as db:
        scan_count = db.query(Scan).count()
    return _json_ok({"status": "operational", "version": __version__, "scans": scan_count})
