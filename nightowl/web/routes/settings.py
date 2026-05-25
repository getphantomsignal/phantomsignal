"""NightOwl Settings Routes — Ghost Key Management & Grid Config"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from nightowl.core.config import config
from nightowl.intel.orchestrator import IntelOrchestrator

settings_bp = Blueprint("settings", __name__)


@settings_bp.route("/")
def settings_page():
    orch = IntelOrchestrator(config)
    all_apis = orch.get_available_apis()
    current_config = config.as_dict()
    return render_template("settings.html", apis=all_apis, config=current_config)


@settings_bp.route("/api-keys", methods=["POST"])
def save_api_keys():
    api_names = request.form.getlist("api_name")
    api_keys = request.form.getlist("api_key")
    saved = 0
    for name, key in zip(api_names, api_keys):
        if name and key and key != "***REDACTED***":
            config.set_api_key(name, key.strip())
            saved += 1
    flash(f"{saved} ghost key(s) uploaded to the vault.", "success")
    return redirect(url_for("settings.settings_page"))


@settings_bp.route("/scraper", methods=["POST"])
def save_scraper_settings():
    config.set("scraper", "respect_robots_txt", value=request.form.get("respect_robots") == "on")
    config.set("scraper", "download_delay", value=float(request.form.get("delay", 1.0)))
    config.set("scraper", "concurrent_requests", value=int(request.form.get("concurrent", 16)))
    config.set("scraper", "tor_enabled", value=request.form.get("tor_enabled") == "on")
    flash("Grid configuration updated.", "success")
    return redirect(url_for("settings.settings_page"))


@settings_bp.route("/api/test/<api_name>")
def test_api(api_name):
    """Test an API key by making a live query."""
    from nightowl.intel.apis.base import get_registered_apis
    import asyncio
    registry = get_registered_apis()
    cls = registry.get(api_name)
    if not cls:
        return jsonify({"status": "error", "message": "API not found"}), 404

    api = cls(config)
    if not api.is_configured:
        return jsonify({"status": "unconfigured", "message": "No API key set"})

    try:
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(asyncio.wait_for(
            api.search("8.8.8.8" if "network" in [c.value for c in api.CATEGORIES] else "google.com"),
            timeout=10,
        ))
        loop.close()
        return jsonify({"status": "ok", "result_count": len(results or [])})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
