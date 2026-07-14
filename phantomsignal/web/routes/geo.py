"""PhantomSignal Geo Recon routes — place → internet-facing assets (spec §13)."""
from __future__ import annotations

import asyncio

from flask import Blueprint, render_template, request

from phantomsignal.core.config import config
from phantomsignal.intel.geo import passive
from phantomsignal.intel.geo.geo_recon import GeoReconEngine, parse_latlon
from phantomsignal.web.routes.locate import _map_cfg

geo_bp = Blueprint("geo", __name__)


@geo_bp.route("/", methods=["GET", "POST"])
def recon():
    result, form = None, {"mode": "free"}
    if request.method == "POST":
        form = {k: (request.form.get(k) or "").strip() for k in
                ("mode", "country", "city", "coords", "radius_km", "org", "domain", "asn")}
        engine = GeoReconEngine(config)
        loop = asyncio.new_event_loop()
        try:
            if form.get("mode") == "shodan":
                latlon = parse_latlon(form.get("coords"))
                coro = engine.recon(
                    country=form.get("country") or None, city=form.get("city") or None,
                    org=form.get("org") or None, domain=form.get("domain") or None,
                    lat=latlon[0] if latlon else None, lon=latlon[1] if latlon else None,
                    radius_km=float(form["radius_km"]) if form.get("radius_km") else None)
            else:
                coro = engine.recon_passive(
                    domain=form.get("domain") or None, asn=passive.parse_asn(form.get("asn")),
                    city=form.get("city") or None, country=form.get("country") or None)
            result = loop.run_until_complete(asyncio.wait_for(coro, timeout=45))
        except Exception:
            result = {"query": None, "assets": [], "summary": {}, "configured": False,
                      "center": None, "error": "recon failed", "mode": form.get("mode")}
        finally:
            loop.close()
    return render_template("geo/recon.html", result=result, form=form, mapcfg=_map_cfg())
