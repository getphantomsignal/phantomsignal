"""PhantomSignal Settings Routes — API key and scan-settings management."""
import asyncio

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from phantomsignal.core.config import config
from phantomsignal.core.proxy_sources import (
    PROXY_SOURCES, fetch_proxy_source, parse_proxy_lines, merge_pool,
)
from phantomsignal.intel.orchestrator import IntelOrchestrator

settings_bp = Blueprint("settings", __name__)

# Bound how big the pool can grow and how much one fetch/upload can add, so a
# multi-thousand-entry feed can't swamp the pool or the settings textarea.
_POOL_CAP = 1000
_ADD_LIMIT = 300


@settings_bp.route("/")
def settings_page():
    """Integrations — API keys and available data sources."""
    orch = IntelOrchestrator(config)
    all_apis = orch.get_available_apis()
    current_config = config.as_dict()
    return render_template("settings.html", apis=all_apis, config=current_config)


@settings_bp.route("/scan")
def scan_settings():
    """Settings — scan behaviour, stealth posture, and egress."""
    return render_template("scan_settings.html", config=config.as_dict(),
                           proxy_sources=PROXY_SOURCES)


def _current_pool():
    return list(config.get("scraper", "proxy_pool", default=[]) or [])


def _apply_pool(additions, origin):
    """Merge new proxies into the in-memory pool and flash the outcome."""
    if not additions:
        flash(f"No valid proxies found in {origin}.", "warning")
        return
    before = _current_pool()
    merged = merge_pool(before, additions, cap=_POOL_CAP)
    config.set("scraper", "proxy_pool", value=merged)
    config.persist()
    added = len(merged) - len(before)
    flash(f"Added {added} new prox{'y' if added == 1 else 'ies'} from {origin} "
          f"— pool now {len(merged)}.", "success")


@settings_bp.route("/proxy/fetch", methods=["POST"])
def fetch_proxies():
    """Seed the pool from a baked-in feed or a custom http(s) list URL."""
    source_key = request.form.get("source", "")
    custom_url = (request.form.get("custom_url") or "").strip()

    if custom_url:
        url = custom_url
        scheme = request.form.get("custom_scheme", "http")
        label = custom_url
    else:
        src = PROXY_SOURCES.get(source_key)
        if not src:
            flash("Unknown proxy source.", "error")
            return redirect(url_for("settings.scan_settings"))
        url, scheme, label = src["url"], src["scheme"], src["name"]

    try:
        loop = asyncio.new_event_loop()
        proxies = loop.run_until_complete(
            fetch_proxy_source(url, default_scheme=scheme, limit=_ADD_LIMIT))
        loop.close()
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("settings.scan_settings"))
    except Exception as e:
        flash(f"Could not fetch proxy list: {e}", "error")
        return redirect(url_for("settings.scan_settings"))

    _apply_pool(proxies, label)
    return redirect(url_for("settings.scan_settings"))


@settings_bp.route("/proxy/upload", methods=["POST"])
def upload_proxies():
    """Seed the pool from an uploaded proxy-list file (one proxy per line)."""
    f = request.files.get("proxy_file")
    if not f or not f.filename:
        flash("No file selected.", "warning")
        return redirect(url_for("settings.scan_settings"))
    scheme = request.form.get("upload_scheme", "http")
    try:
        text = f.read().decode("utf-8", errors="ignore")
    except Exception as e:
        flash(f"Could not read file: {e}", "error")
        return redirect(url_for("settings.scan_settings"))

    proxies = parse_proxy_lines(text, default_scheme=scheme, limit=_ADD_LIMIT)
    _apply_pool(proxies, f.filename)
    return redirect(url_for("settings.scan_settings"))


@settings_bp.route("/api-keys", methods=["POST"])
def save_api_keys():
    api_names = request.form.getlist("api_name")
    api_keys = request.form.getlist("api_key")
    saved = 0
    for name, key in zip(api_names, api_keys):
        if name and key and key != "***REDACTED***":
            config.set_api_key(name, key.strip())
            saved += 1
    flash(f"{saved} API key(s) saved.", "success")
    return redirect(url_for("settings.settings_page"))


@settings_bp.route("/scraper", methods=["POST"])
def save_scraper_settings():
    config.set("scraper", "respect_robots_txt", value=request.form.get("respect_robots") == "on")
    config.set("scraper", "download_delay", value=float(request.form.get("delay", 1.0)))
    config.set("scraper", "concurrent_requests", value=int(request.form.get("concurrent", 16)))
    config.set("scraper", "tor_enabled", value=request.form.get("tor_enabled") == "on")

    profile = request.form.get("stealth_profile", "off")
    if profile not in ("off", "quiet", "paranoid"):
        profile = "off"
    config.set("scraper", "stealth_profile", value=profile)
    proxy = (request.form.get("proxy") or "").strip()
    config.set("scraper", "proxy", value=proxy or None)

    # Rotating egress pool — one proxy URL per line.
    pool_raw = request.form.get("proxy_pool") or ""
    pool = [ln.strip() for ln in pool_raw.splitlines() if ln.strip()]
    config.set("scraper", "proxy_pool", value=pool)
    rotation = request.form.get("proxy_rotation", "sticky")
    if rotation not in ("sticky", "every"):
        rotation = "sticky"
    config.set("scraper", "proxy_rotation", value=rotation)
    config.set("scraper", "tls_impersonate", value=request.form.get("tls_impersonate") == "on")

    config.persist()
    flash("Settings saved.", "success")
    return redirect(url_for("settings.scan_settings"))


@settings_bp.route("/api/test/<api_name>")
def test_api(api_name):
    """Test an API key by making a live query."""
    from phantomsignal.intel.apis.base import get_registered_apis, APIAuthError
    import asyncio
    registry = get_registered_apis()
    cls = registry.get(api_name)
    if not cls:
        return jsonify({"status": "error", "message": "API not found"}), 404

    api = cls(config)
    if not api.is_configured:
        return jsonify({"status": "unconfigured", "message": "No API key set"})

    probe = "8.8.8.8" if "network" in [c.value for c in api.CATEGORIES] else "google.com"
    try:
        loop = asyncio.new_event_loop()
        results = loop.run_until_complete(asyncio.wait_for(api.search(probe), timeout=15))
        loop.close()
        return jsonify({"status": "ok", "result_count": len(results or [])})
    except APIAuthError as e:
        return jsonify({"status": "invalid_key", "message": f"Key rejected by API (HTTP {e.status_code})"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
