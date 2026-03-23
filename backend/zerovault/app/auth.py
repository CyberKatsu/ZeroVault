"""
zerovault.auth
==============
JWT token creation and verification.

We use PyJWT rather than python-jose because python-jose has known CVEs
(CVE-2024-33663, CVE-2024-33664) related to algorithm confusion attacks.
PyJWT with explicit algorithm specification is the current recommended approach.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from zerovault.app.config import Settings, get_settings

bearer_scheme = HTTPBearer()


def create_access_token(
    subject: str,
    settings: Settings,
) -> str:
    """
    Create a signed JWT access token.

    Parameters
    ----------
    subject : str
        The user identifier (username) to embed as the 'sub' claim.
    settings : Settings
        Application settings (secret key, algorithm, expiry).

    Returns
    -------
    str
        Encoded JWT string.
    """
    now = datetime.now(tz=timezone.utc)
    expire = now + timedelta(minutes=settings.jwt_access_token_expire_minutes)
    payload: dict[str, str | datetime] = {
        "sub": subject,
        "iat": now,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str, settings: Settings) -> str:
    """
    Decode and verify a JWT, returning the subject (username).

    Raises
    ------
    jwt.PyJWTError
        On any verification failure (expired, invalid signature, etc.)
    """
    payload = jwt.decode(
        token,
        settings.jwt_secret_key,
        algorithms=[settings.jwt_algorithm],
    )
    sub: str | None = payload.get("sub")
    if sub is None:
        raise jwt.InvalidTokenError("Token has no 'sub' claim.")
    return sub


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(bearer_scheme)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> str:
    """
    FastAPI dependency: extract and verify Bearer JWT, return username.

    Raises HTTP 401 on any authentication failure.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        username = decode_access_token(credentials.credentials, settings)
    except jwt.PyJWTError:
        raise credentials_exception
    return username
