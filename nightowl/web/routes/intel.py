"""NightOwl Intel Routes — People Search & Shadow Profiling"""
from flask import Blueprint, render_template, request, jsonify
from nightowl.intel.people.aggregator import ShadowProfileBuilder
from nightowl.core.config import config
import asyncio

intel_bp = Blueprint("intel", __name__)


@intel_bp.route("/")
def intel_search():
    from nightowl.intel.orchestrator import IntelOrchestrator
    orch = IntelOrchestrator(config)
    apis = orch.get_available_apis()
    return render_template("intel/search.html", apis=apis)


@intel_bp.route("/person", methods=["POST"])
def person_search():
    first_name = request.form.get("first_name", "").strip()
    last_name = request.form.get("last_name", "").strip()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    username = request.form.get("username", "").strip()
    address = request.form.get("address", "").strip()

    if not any([first_name, last_name, email, phone, username]):
        return render_template("intel/search.html", error="At least one identifier required.")

    builder = ShadowProfileBuilder(config)
    loop = asyncio.new_event_loop()
    try:
        profile = loop.run_until_complete(builder.build_profile(
            first_name=first_name or None,
            last_name=last_name or None,
            email=email or None,
            phone=phone or None,
            username=username or None,
            address=address or None,
        ))
    finally:
        loop.close()

    return render_template("intel/results.html", profile=profile, query={
        "first_name": first_name, "last_name": last_name, "email": email,
        "phone": phone, "username": username,
    })


@intel_bp.route("/api/person", methods=["POST"])
def api_person_search():
    data = request.get_json() or {}
    builder = ShadowProfileBuilder(config)
    loop = asyncio.new_event_loop()
    try:
        profile = loop.run_until_complete(builder.build_profile(**data))
    finally:
        loop.close()
    return jsonify(profile)
