"""
PhantomSignal Web Interface — The Shadow Grid Control Panel
Flask + SocketIO powered cyberpunk OSINT dashboard.

Author:  the-clipper
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
from __future__ import annotations

import asyncio
import logging
import threading
from datetime import datetime
from typing import Optional

from flask import Flask
from flask_socketio import SocketIO, emit, join_room, leave_room

from phantomsignal import __version__, __codename__
from phantomsignal.core.config import config as phantomsignal_config
from phantomsignal.core.database import init_db

logger = logging.getLogger("phantomsignal.web")

socketio = SocketIO(async_mode="threading", cors_allowed_origins="*", logger=False)


def create_app(config_path: Optional[str] = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")

    app.config["SECRET_KEY"] = phantomsignal_config.get("server", "secret_key")
    app.config["SQLALCHEMY_DATABASE_URI"] = phantomsignal_config.get("database", "url", default="sqlite:///phantomsignal.db")
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["PHANTOMSIGNAL_VERSION"] = __version__
    app.config["PHANTOMSIGNAL_CODENAME"] = __codename__

    init_db()

    from phantomsignal.core.engine import engine as phantom_engine
    phantom_engine._socketio = socketio
    app.phantom_engine = phantom_engine

    socketio.init_app(app)

    from phantomsignal.web.routes.dashboard import dashboard_bp
    from phantomsignal.web.routes.scans import scans_bp
    from phantomsignal.web.routes.intel import intel_bp
    from phantomsignal.web.routes.settings import settings_bp
    from phantomsignal.web.routes.export import export_bp
    from phantomsignal.web.routes.api import api_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(scans_bp, url_prefix="/scans")
    app.register_blueprint(intel_bp, url_prefix="/intel")
    app.register_blueprint(settings_bp, url_prefix="/settings")
    app.register_blueprint(export_bp, url_prefix="/export")
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    @app.context_processor
    def inject_globals():
        return {
            "now": datetime.utcnow(),
            "version": __version__,
            "codename": __codename__,
        }

    @app.errorhandler(404)
    def page_not_found(e):
        from flask import render_template
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_error(e):
        from flask import render_template
        return render_template("errors/500.html"), 500

    _register_socketio_handlers(app)

    return app


def _register_socketio_handlers(app: Flask) -> None:
    @socketio.on("connect")
    def on_connect():
        emit("server_ready", {
            "message": "Connected. Ready to scan.",
            "version": __version__,
            "codename": __codename__,
        })

    @socketio.on("disconnect")
    def on_disconnect():
        logger.debug("Client disconnected from the grid")

    @socketio.on("join_scan")
    def on_join_scan(data):
        scan_id = data.get("scan_id")
        if scan_id:
            join_room(f"scan_{scan_id}")
            emit("joined_scan", {"scan_id": scan_id, "message": f"Connected to scan {scan_id[:8]}..."})
            # Send current progress so late-joining browsers can sync immediately.
            with app.app_context():
                from phantomsignal.core.database import get_db
                from phantomsignal.core.models import Scan
                try:
                    with get_db() as db:
                        scan = db.query(Scan).filter(Scan.id == scan_id).first()
                        if scan and scan.status.value == "running":
                            emit("scan_status", {
                                "scan_id": scan_id,
                                "progress": scan.progress or 0,
                                "status": scan.status.value,
                            })
                except Exception:
                    pass

    @socketio.on("leave_scan")
    def on_leave_scan(data):
        scan_id = data.get("scan_id")
        if scan_id:
            leave_room(f"scan_{scan_id}")

    @socketio.on("abort_scan")
    def on_abort_scan(data):
        scan_id = data.get("scan_id")
        if scan_id:
            app.phantom_engine.abort_scan(scan_id)
            emit("scan_aborted", {"scan_id": scan_id})

    @socketio.on("ping")
    def on_ping():
        emit("pong", {"timestamp": datetime.utcnow().isoformat()})


def run_scan_async(app: Flask, scan_id: str) -> None:
    """Launch a scan in a background thread with its own asyncio loop."""
    def _run():
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        with app.app_context():
            loop.run_until_complete(app.phantom_engine.launch_scan(scan_id))
        loop.close()

    thread = threading.Thread(target=_run, daemon=True, name=f"scan-{scan_id[:8]}")
    thread.start()
