#!/usr/bin/env python3
"""
NightOwl — Production launch script

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
import os, sys

if __name__ == "__main__":
    from nightowl.core.config import config
    from nightowl.core.database import init_db
    from nightowl.web.app import create_app, socketio

    init_db()
    app = create_app()

    host = os.getenv("NIGHTOWL_HOST", config.get("server", "host", default="127.0.0.1"))
    port = int(os.getenv("NIGHTOWL_PORT", config.get("server", "port", default=5000)))
    debug = os.getenv("NIGHTOWL_DEBUG", str(config.get("server", "debug", default=False))).lower() == "true"

    print(f"\n🦉 NightOwl // Phantom Signal — v{__import__('nightowl').__version__}")
    print(f"   Grid online: http://{host}:{port}\n")

    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False, allow_unsafe_werkzeug=True)
