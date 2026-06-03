"""PhantomSignal Dashboard Route"""
from flask import Blueprint, render_template
from phantomsignal.core.database import get_db
from phantomsignal.core.models import Scan, ScanStatus, ThreatLevel

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
def index():
    with get_db() as db:
        total_scans = db.query(Scan).count()
        active_scans = db.query(Scan).filter(Scan.status == ScanStatus.RUNNING).count()
        recent_scans = db.query(Scan).order_by(Scan.created_at.desc()).limit(8).all()
        critical_scans = db.query(Scan).filter(
            Scan.threat_level == ThreatLevel.CRITICAL
        ).count()

        from phantomsignal.core.models import ScanResult
        total_results = db.query(ScanResult).count()

        stats = {
            "total_scans": total_scans,
            "active_scans": active_scans,
            "total_results": total_results,
            "critical_threats": critical_scans,
        }
        recent = [s.to_dict() for s in recent_scans]

    from phantomsignal.intel.orchestrator import IntelOrchestrator
    from phantomsignal.core.config import config
    orch = IntelOrchestrator(config)
    api_status = orch.get_api_status()
    configured_apis = sum(1 for a in api_status if a.get("is_configured"))

    return render_template(
        "dashboard.html",
        stats=stats,
        recent_scans=recent,
        api_status=api_status,
        configured_apis=configured_apis,
    )


@dashboard_bp.route("/about")
def about():
    from phantomsignal import __version__, __codename__, DISCLAIMER
    return render_template("about.html", version=__version__, codename=__codename__, disclaimer=DISCLAIMER)
