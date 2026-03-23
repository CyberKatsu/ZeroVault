"""
tests/conftest.py
=================
Shared pytest fixtures for ZeroVault.

Design decisions
----------------
1. We use SQLite (aiosqlite) for tests, not PostgreSQL.
   - No running database required in CI.
   - SQLAlchemy's async ORM is dialect-agnostic for our schema.
   - aiosqlite is pip-installable; no Docker needed in CI.

2. Each test gets a FRESH database engine (function-scoped).
   Sharing an engine across tests risks state leakage via leftover rows.
   Function scope ensures complete isolation at the cost of slightly slower
   startup — acceptable because table creation is fast with SQLite in-memory.

3. Cryptographic fixtures use REAL operations — no mocks.
   This validates that the crypto primitives integrate correctly end-to-end.
   The only concession to speed is reducing Argon2 parameters to their
   minimums for tests (t=1, m=8, p=1) so each KDF call takes < 5 ms.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from zerovault.app.config import Settings
from zerovault.app.database import get_db
from zerovault.app.main import app
from zerovault.app.models import Base

# ── Minimal Argon2 parameters for fast tests ─────────────────────────────────
# These are well below recommended production values.  They are used ONLY in
# tests where we need to call derive_keys many times without waiting seconds.
TEST_ARGON2_TIME_COST = 1
TEST_ARGON2_MEMORY_COST_KIB = 8  # 8 KiB — absolute minimum for argon2-cffi
TEST_ARGON2_PARALLELISM = 1

TEST_MASTER_PASSWORD = "correct horse battery staple"
TEST_USERNAME = "alice"


def get_test_settings() -> Settings:
    return Settings(
        database_url="sqlite+aiosqlite:///:memory:",
        jwt_secret_key="test-secret-key-not-for-production",
        jwt_access_token_expire_minutes=5,
        debug=False,
    )


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """
    Provide a fresh in-memory SQLite session for each test.

    Uses aiosqlite via the `sqlite+aiosqlite` driver URL.  All tables are
    created at fixture setup and dropped (along with the in-memory DB) at
    teardown.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
        autoflush=False,
        autocommit=False,
    )

    async with session_factory() as session:
        yield session

    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def async_client(db_session: AsyncSession):
    """
    Provide an HTTPX AsyncClient wired to the FastAPI app with an overridden
    database dependency pointing at the test in-memory SQLite DB.
    """
    async def override_get_db():
        try:
            yield db_session
            await db_session.commit()
        except Exception:
            await db_session.rollback()
            raise

    app.dependency_overrides[get_db] = override_get_db

    settings = get_test_settings()
    from zerovault.app.config import get_settings
    app.dependency_overrides[get_settings] = lambda: settings

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()
