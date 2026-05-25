"""NightOwl Export Routes — Intel Packet Compilation"""
from flask import Blueprint, render_template, request, jsonify, send_file, flash, redirect, url_for
from nightowl.exporters.manager import ExportManager
from nightowl.core.database import get_db
from nightowl.core.models import Scan
import os

export_bp = Blueprint("export", __name__)


@export_bp.route("/<scan_id>")
def export_options(scan_id):
    with get_db() as db:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            flash("Scan not found.", "error")
            return redirect(url_for("scans.list_scans"))
        scan_dict = scan.to_dict()
    return render_template("export.html", scan=scan_dict)


@export_bp.route("/<scan_id>/generate", methods=["POST"])
def generate_export(scan_id):
    fmt = request.form.get("format", "json")
    compress = request.form.get("compress") == "on"
    encrypt = request.form.get("encrypt") == "on"
    password = request.form.get("password", "").strip() or None

    if encrypt and not password:
        flash("Encryption password required.", "error")
        return redirect(url_for("export.export_options", scan_id=scan_id))

    try:
        manager = ExportManager()
        result = manager.export(
            scan_id=scan_id,
            fmt=fmt,
            compress=compress,
            encrypt=encrypt,
            encryption_password=password,
        )
        return send_file(
            result["file_path"],
            as_attachment=True,
            download_name=result["file_name"],
        )
    except Exception as e:
        flash(f"Export failed: {e}", "error")
        return redirect(url_for("export.export_options", scan_id=scan_id))


@export_bp.route("/api/<scan_id>", methods=["POST"])
def api_export(scan_id):
    data = request.get_json() or {}
    try:
        manager = ExportManager()
        result = manager.export(
            scan_id=scan_id,
            fmt=data.get("format", "json"),
            compress=data.get("compress", False),
            encrypt=data.get("encrypt", False),
            encryption_password=data.get("password"),
        )
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 400
