"""
zerovault.main
==============
FastAPI application factory and startup logic.

Lifecycle
---------
On startup:  create all database tables (idempotent via CREATE TABLE IF NOT EXISTS).
On shutdown: dispose the connection pool cleanly.

In production you would use Alembic migrations instead of create_all.
The create_all call here is retained for ease of local development and tests.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from zerovault.app.config import get_settings
from zerovault.app.database import engine
from zerovault.app.models import Base
from zerovault.app.routers import auth_router, vault_router

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Create tables on startup; dispose engine on shutdown."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    description=(
        "Zero-knowledge password manager API. "
        "The server never sees plaintext passwords, vault entries, or encryption keys."
    ),
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS: allow the Reflex frontend (runs on port 3000 by default)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(vault_router)


@app.get("/health", tags=["health"])
async def health_check() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}
