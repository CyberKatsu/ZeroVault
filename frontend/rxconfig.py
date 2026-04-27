import os

import reflex as rx

config = rx.Config(
    app_name="zerovault",
    frontend_port=int(os.getenv("ZV_FRONTEND_PORT", "37420")),
    backend_port=int(os.getenv("ZV_REFLEX_BACKEND_PORT", "38171")),
    # REFLEX_API_URL is the URL the *browser* uses to reach the Reflex WebSocket backend.
    # In Docker the internal port (8001) is mapped to a host port (38171 by default),
    # so we allow overriding via REFLEX_API_URL to point at the host-facing port.
    api_url=os.getenv("REFLEX_API_URL", f"http://localhost:{os.getenv('ZV_REFLEX_BACKEND_PORT', '38171')}"),
    env=rx.Env.DEV,
)
