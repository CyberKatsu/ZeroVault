import os

import reflex as rx

config = rx.Config(
    app_name="zerovault",
    frontend_port=int(os.getenv("ZV_FRONTEND_PORT", "37420")),
    backend_port=int(os.getenv("ZV_REFLEX_BACKEND_PORT", "38171")),
    api_url=f"http://localhost:{os.getenv('ZV_REFLEX_BACKEND_PORT', '38171')}",
    env=rx.Env.DEV,
)
