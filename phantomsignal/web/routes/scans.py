"""PhantomSignal Scan Routes — scan launch, listing, and results."""
from __future__ import annotations


from flask import (
    Blueprint, current_app, flash, redirect,
    render_template, request, url_for
)

from phantomsignal.core.database import get_db
from phantomsignal.core.models import Scan, ScanResult, ScanType

scans_bp = Blueprint("scans", __name__)


@scans_bp.route("/")
def list_scans():
    with get_db() as db:
        scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(100).all()
        scan_list = [s.to_dict() for s in scans]
    return render_template("scans/list.html", scans=scan_list)


@scans_bp.route("/new")
def new_scan():
    from phantomsignal.intel.orchestrator import IntelOrchestrator
    from phantomsignal.core.config import config
    orchestrator = IntelOrchestrator(config)
    api_status = orchestrator.get_api_status()
    return render_template("scans/new.html", api_status=api_status)


@scans_bp.route("/launch", methods=["POST"])
def launch_scan():
    from phantomsignal.web.app import run_scan_async

    target = request.form.get("target", "").strip()
    if not target:
        flash("Target required.", "error")
        return redirect(url_for("scans.new_scan"))

    name = request.form.get("name", f"Scan — {target[:30]}")
    scan_type_str = request.form.get("scan_type", "web_recon")
    profile = request.form.get("profile", "standard")
    modules = request.form.getlist("modules")

    recursive = request.form.get("recursive") == "on"
    signatures = request.form.get("signatures") == "on"

    options = {
        "depth": int(request.form.get("depth", 2)),
        "ports": request.form.get("port_profile", "common"),
        "respect_robots": request.form.get("respect_robots") == "on",
        "evasive": request.form.get("evasive") == "on",
        # Attack-surface pipeline (Phase 1)
        "recursive": recursive,
        "max_depth": int(request.form.get("max_depth", 2)),
        "allow_cross_domain": request.form.get("allow_cross_domain") == "on",
        "signatures": signatures,
    }

    try:
        scan_type = ScanType(scan_type_str)
    except ValueError:
        scan_type = ScanType.WEB_RECON

    modules_enabled = modules or ["dns_recon", "port_scan", "tech_detect", "api_hunt", "intel"]
    # The pipeline runs inside the intel orchestrator — ensure it's active when requested.
    if (recursive or signatures) and "intel" not in modules_enabled:
        modules_enabled = [*modules_enabled, "intel"]

    with get_db() as db:
        scan = Scan(
            name=name,
            target=target,
            scan_type=scan_type,
            profile=profile,
            modules_enabled=modules_enabled,
            options=options,
            tags=request.form.getlist("tags"),
        )
        db.add(scan)
        db.flush()
        scan_id = scan.id

    run_scan_async(current_app._get_current_object(), scan_id)

    flash(f"Scan started for {target}.", "success")
    return redirect(url_for("scans.scan_results", scan_id=scan_id))


@scans_bp.route("/<scan_id>")
def scan_results(scan_id):
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            flash("Scan not found.", "error")
            return redirect(url_for("scans.list_scans"))
        scan_dict = scan.to_dict()
        results = db.query(ScanResult).filter(
            ScanResult.scan_id == scan_id
        ).order_by(ScanResult.relevance_score.desc()).all()
        results_list = [r.to_dict() for r in results]

    grouped = {}
    for r in results_list:
        module = r.get("module", "unknown")
        if module not in grouped:
            grouped[module] = []
        grouped[module].append(r)

    return render_template(
        "scans/results.html",
        scan=scan_dict,
        results=results_list,
        grouped_results=grouped,
        is_live=scan_dict["status"] == "running",
    )


@scans_bp.route("/<scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if scan:
            db.delete(scan)
    flash("Scan deleted.", "success")
    return redirect(url_for("scans.list_scans"))


@scans_bp.route("/<scan_id>/abort", methods=["POST"])
def abort_scan(scan_id):
    aborted = current_app.phantom_engine.abort_scan(scan_id)
    if aborted:
        flash("Scan stopped.", "warning")
    return redirect(url_for("scans.scan_results", scan_id=scan_id))


@scans_bp.route("/<scan_id>/rescan", methods=["POST"])
def rescan(scan_id):
    """Re-run an existing scan against the same target with the same config."""
    from phantomsignal.web.app import run_scan_async

    with get_db() as db:
        original = db.query(Scan).filter(Scan.id == scan_id).first()
        if not original:
            flash("Scan not found.", "error")
            return redirect(url_for("scans.list_scans"))

        target = original.target
        new_scan = Scan(
            name=f"Re-scan — {target[:30]}",
            target=target,
            scan_type=original.scan_type,
            profile=original.profile,
            modules_enabled=list(original.modules_enabled or []),
            options=dict(original.options or {}),
            tags=list(original.tags or []),
        )
        db.add(new_scan)
        db.flush()
        new_id = new_scan.id

    run_scan_async(current_app._get_current_object(), new_id)

    flash(f"Re-scanning {target}.", "success")
    return redirect(url_for("scans.scan_results", scan_id=new_id))
