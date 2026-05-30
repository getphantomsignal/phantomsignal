#!/usr/bin/env python3
"""
OwlScan — Production launch script

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
import os, sys

if __name__ == "__main__":
    from owlscan.core.config import config
    from owlscan.core.database import init_db
    from owlscan.web.app import create_app, socketio

    init_db()
    app = create_app()

    host = os.getenv("OWLSCAN_HOST", config.get("server", "host", default="127.0.0.1"))
    port = int(os.getenv("OWLSCAN_PORT", config.get("server", "port", default=5000)))
    debug = os.getenv("OWLSCAN_DEBUG", str(config.get("server", "debug", default=False))).lower() == "true"

    print(f"\n🦉 OwlScan // Phantom Signal — v{__import__('owlscan').__version__}")
    print(f"   Grid online: http://{host}:{port}\n")

    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False, allow_unsafe_werkzeug=True)
