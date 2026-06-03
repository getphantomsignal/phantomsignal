#!/usr/bin/env python3
"""
PhantomSignal — Production launch script

Author:  packetsn1ffer
AI:      Claude (Anthropic)
License: MIT — see LICENSE
"""
import os, sys

if __name__ == "__main__":
    from phantomsignal.core.config import config
    from phantomsignal.core.database import init_db
    from phantomsignal.web.app import create_app, socketio

    init_db()
    app = create_app()

    host = os.getenv("PHANTOMSIGNAL_HOST", config.get("server", "host", default="127.0.0.1"))
    port = int(os.getenv("PHANTOMSIGNAL_PORT", config.get("server", "port", default=5000)))
    debug = os.getenv("PHANTOMSIGNAL_DEBUG", str(config.get("server", "debug", default=False))).lower() == "true"

    print(f"\n>> PhantomSignal // OSINT Framework — v{__import__('phantomsignal').__version__}")
    print(f"   Grid online: http://{host}:{port}\n")

    socketio.run(app, host=host, port=port, debug=debug, use_reloader=False, allow_unsafe_werkzeug=True)
