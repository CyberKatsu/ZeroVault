import reflex as rx

config = rx.Config(
    app_name="zerovault",
    frontend_port=3000,
    backend_port=8001,  # Reflex's own backend; FastAPI runs on 8000
    api_url="http://localhost:8001",
    env=rx.Env.DEV,
)
