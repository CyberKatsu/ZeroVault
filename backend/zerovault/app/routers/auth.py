"""
zerovault.routers.auth
======================
Authentication endpoints: registration, KDF parameter retrieval, and login.

Endpoint summary
----------------
POST /auth/register   — create account, store bcrypt(auth_key) + KDF params
GET  /auth/kdf-params — return Argon2 salt + params for a given username
POST /auth/login      — verify auth_key, issue JWT
"""

from __future__ import annotations

import asyncio
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from zerovault.app.auth import create_access_token
from zerovault.app.config import Settings, get_settings
from zerovault.app.crypto.auth_key import hash_auth_key, verify_auth_key
from zerovault.app.database import get_db
from zerovault.app.models import User
from zerovault.app.schemas import (
    KDFParamsResponse,
    LoginRequest,
    LoginResponse,
    RegisterRequest,
    RegisterResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=RegisterResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account.",
)
async def register(
    payload: RegisterRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> RegisterResponse:
    """
    Register a new user.

    The client has already:
    1. Generated a random Argon2 salt.
    2. Run Argon2id(master_password, salt) → master_key_material.
    3. Run HKDF → enc_key (discarded locally) + auth_key.
    4. Sent auth_key_hex and the KDF parameters to this endpoint.

    The server:
    - Verifies the username is not taken.
    - bcrypt-hashes auth_key and stores the hash.
    - Stores the KDF parameters so the client can re-derive auth_key at login.
    - NEVER sees the master password or enc_key.
    """
    # Check username uniqueness
    existing = await db.scalar(select(User).where(User.username == payload.username))
    if existing is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already taken.",
        )

    auth_key_bytes = bytes.fromhex(payload.auth_key_hex)

    # bcrypt is CPU-bound and blocking.  Run in executor to avoid blocking
    # the async event loop during the ≈250 ms bcrypt operation.
    loop = asyncio.get_event_loop()
    auth_key_hash: str = await loop.run_in_executor(
        None, hash_auth_key, auth_key_bytes
    )

    user = User(
        username=payload.username,
        auth_key_hash=auth_key_hash,
        argon2_salt=payload.argon2_salt_hex,
        argon2_time_cost=payload.argon2_time_cost,
        argon2_memory_cost_kib=payload.argon2_memory_cost_kib,
        argon2_parallelism=payload.argon2_parallelism,
    )
    db.add(user)
    await db.flush()  # Populate user.id before commit

    return RegisterResponse(user_id=user.id, username=user.username)


@router.get(
    "/kdf-params/{username}",
    response_model=KDFParamsResponse,
    summary="Return KDF parameters for a username so the client can re-derive auth_key.",
)
async def get_kdf_params(
    username: str,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> KDFParamsResponse:
    """
    Return stored Argon2 parameters for the given username.

    Called by the client BEFORE the login step so that the client can derive
    auth_key locally using the correct parameters.

    Security note — user enumeration
    ----------------------------------
    This endpoint reveals whether a username exists.  An alternative design
    would return synthetic parameters for unknown usernames (derived from a
    server-side secret + username via HMAC) to prevent enumeration.  For a
    portfolio project, the current direct approach is acceptable.  The
    SECURITY.md documents this as a known limitation.
    """
    user = await db.scalar(select(User).where(User.username == username))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )

    return KDFParamsResponse(
        argon2_salt_hex=user.argon2_salt,
        argon2_time_cost=user.argon2_time_cost,
        argon2_memory_cost_kib=user.argon2_memory_cost_kib,
        argon2_parallelism=user.argon2_parallelism,
    )


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Verify auth_key and issue a JWT access token.",
)
async def login(
    payload: LoginRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> LoginResponse:
    """
    Authenticate a user and return a JWT.

    The client:
    1. Retrieved KDF params from /auth/kdf-params/{username}.
    2. Ran Argon2id + HKDF to derive auth_key locally.
    3. Sends auth_key_hex here.

    The server:
    - Looks up the user's bcrypt hash.
    - Calls bcrypt.checkpw(auth_key, stored_hash).
    - On success, issues a JWT signed with the server's secret key.
    - NEVER derives or stores enc_key.
    """
    user = await db.scalar(select(User).where(User.username == payload.username))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    auth_key_bytes = bytes.fromhex(payload.auth_key_hex)

    # Run bcrypt in executor (blocking, ≈250 ms at work factor 12)
    loop = asyncio.get_event_loop()
    is_valid: bool = await loop.run_in_executor(
        None, verify_auth_key, auth_key_bytes, user.auth_key_hash
    )

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    access_token = create_access_token(subject=user.username, settings=settings)
    return LoginResponse(access_token=access_token)
