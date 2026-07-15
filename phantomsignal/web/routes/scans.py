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


# ── Semantic categories for the single-page summary view ──────────────────
# Groups the ~30 raw result_types into a handful of human-facing buckets so the
# summary page reads by subject area rather than by which module produced it.
# Ordered to mirror an external recon → attack workflow that both red and blue
# teams recognise: footprint the namespace, map the perimeter, pivot on certs,
# enumerate the web surface, fingerprint the stack, probe mail/services,
# corroborate with external intel, and finish on the actionable exposures.
# label / icon / accent drive the section chrome in scans/summary.html.
RESULT_CATEGORIES = [
    ("dns",      "DNS & Domains",            "⊚", "cyan", {
        "dns_records", "dnssec", "zone_transfer", "subdomain",
        "subdomain_summary",
    }),
    ("network",  "Network & Infrastructure", "◈", "cyan", {
        "ip_address", "ip_geolocation", "reverse_dns", "open_port",
        "port_scan_summary", "os_detection", "infra_sibling", "shodan_host",
        "cdn_detected", "origin_candidate",
    }),
    ("tls",      "TLS & Certificates",       "⛨", "green", {
        "tls_certificate", "cert_transparency", "tls_cert_fingerprint",
        "jarm_fingerprint", "favicon_hash",
    }),
    ("web",      "Web & Endpoints",          "⌘", "cyan", {
        "web_resource", "api_endpoint", "graphql_schema", "http_headers",
        "js_endpoint", "js_mine_summary", "archive_url", "archive_summary",
    }),
    ("tech",     "Technology Stack",         "⚙", "cyan", {
        "technology",
    }),
    ("email",    "Email & Services",         "✉", "orange", {
        "email_security", "smtp_users", "smtp_open_relay", "snmp_community",
    }),
    ("intel",    "Threat Intelligence",      "◎", "purple", {
        "otx_indicator", "urlscan_result", "whois_record",
        "securitytrails_whois",
    }),
    ("findings", "Findings & Exposure",      "⚠", "red", {
        "signature_match", "dork", "security_posture", "js_secret",
        "takeover_vulnerable", "takeover_candidate", "takeover_confirmed",
        "origin_confirmed", "vulnerability", "vuln_scan_summary",
    }),
]

# Severity ranking for the Findings & Exposure category — drives worst-first
# sort order and the Critical/High/Medium/Low breakdowns in the header, tile,
# and jump-nav chip.
_SEV_ORDER = ["critical", "high", "medium", "low", "info"]
_SEV_RANK = {lvl: i for i, lvl in enumerate(_SEV_ORDER)}


def _finding_severity(result: dict) -> str:
    """Normalise a Findings result to one of _SEV_ORDER."""
    data = result.get("data") or {}
    rtype = result.get("result_type")
    sev = str(data.get("severity") or "").lower()
    if sev in _SEV_RANK:
        return sev
    if rtype == "takeover_confirmed":
        return "critical"
    if rtype == "takeover_vulnerable":
        return "high"
    if rtype == "takeover_candidate":
        return "medium"
    if rtype == "security_posture":
        rating = str(data.get("rating") or "").upper()
        return {"F": "critical", "D": "high", "C": "medium",
                "B": "low", "A": "info"}.get(rating, "medium")
    return "info"


_TYPE_TO_CATEGORY = {
    rtype: key
    for key, _label, _icon, _accent, types in RESULT_CATEGORIES
    for rtype in types
}
_CATEGORY_META = {
    key: {"label": label, "icon": icon, "accent": accent}
    for key, label, icon, accent, _types in RESULT_CATEGORIES
}
_CATEGORY_ORDER = [key for key, *_ in RESULT_CATEGORIES] + ["other"]


@scans_bp.route("/<scan_id>/summary")
def scan_summary(scan_id):
    """Single-page view: every result at once, grouped into semantic categories."""
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

    # The OPSEC attribution surface is operator telemetry, not a target finding —
    # pull it out so it renders as its own panel instead of a category bucket.
    attribution = next(
        (r.get("data") for r in results_list
         if r.get("result_type") == "attribution_surface"), None
    )
    results_list = [r for r in results_list
                    if r.get("result_type") != "attribution_surface"]

    # Bucket results into categories, preserving the relevance ordering above.
    categories = []
    seen = {}
    for r in results_list:
        key = _TYPE_TO_CATEGORY.get(r.get("result_type"), "other")
        seen.setdefault(key, []).append(r)

    for key in _CATEGORY_ORDER:
        items = seen.get(key)
        if not items:
            continue
        meta = _CATEGORY_META.get(key, {"label": "Other", "icon": "▪", "accent": "cyan"})

        # Findings get a severity grade, a worst-first sort, and a histogram
        # that feeds the section header, the overview tile, and the nav chip.
        severity = None
        if key == "findings":
            for it in items:
                it["severity"] = _finding_severity(it)
            items.sort(key=lambda it: _SEV_RANK.get(it["severity"], 99))
            severity = {lvl: sum(1 for it in items if it["severity"] == lvl)
                        for lvl in _SEV_ORDER}

        categories.append({
            "key": key,
            "label": meta["label"],
            "icon": meta["icon"],
            "accent": meta["accent"],
            "entries": items,
            "count": len(items),
            "anomaly_count": sum(1 for i in items if i.get("is_anomaly")),
            "severity": severity,
        })

    return render_template(
        "scans/summary.html",
        scan=scan_dict,
        results=results_list,
        categories=categories,
        attribution=attribution,
        anomaly_count=sum(1 for r in results_list if r.get("is_anomaly")),
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
