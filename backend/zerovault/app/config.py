"""
zerovault.config
================
Environment-driven configuration using pydantic-settings.

All secrets are loaded from environment variables (or a .env file during
development).  They are never hardcoded in source.
"""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Database ─────────────────────────────────────────────────────────────
    database_url: str = (
        "postgresql+asyncpg://zerovault:zerovault@localhost:5432/zerovault"
    )

    # ── JWT ───────────────────────────────────────────────────────────────────
    # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
    jwt_secret_key: str = "CHANGE_ME_IN_PRODUCTION_generate_with_secrets_token_hex"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 60

    # ── Application ───────────────────────────────────────────────────────────
    app_name: str = "ZeroVault"
    debug: bool = False


@lru_cache
def get_settings() -> Settings:
    """Return a cached settings singleton.  Suitable for FastAPI Depends()."""
    return Settings()
