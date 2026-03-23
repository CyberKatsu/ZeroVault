"""
zerovault.routers.vault
=======================
Vault management endpoints.

All operations require a valid JWT (Authorization: Bearer <token>).
The server handles only ciphertext — it has no ability to decrypt entries.

Endpoint summary
----------------
POST   /vault/entries          — store a new encrypted vault entry
GET    /vault/entries          — list all encrypted entries for the current user
DELETE /vault/entries/{id}     — delete a specific entry
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from zerovault.app.auth import get_current_user
from zerovault.app.database import get_db
from zerovault.app.models import User, VaultEntry
from zerovault.app.schemas import (
    DeleteResponse,
    VaultEntryCreate,
    VaultEntryResponse,
)

router = APIRouter(prefix="/vault", tags=["vault"])

CurrentUser = Annotated[str, Depends(get_current_user)]
DB = Annotated[AsyncSession, Depends(get_db)]


async def _get_user_or_404(username: str, db: AsyncSession) -> User:
    user = await db.scalar(select(User).where(User.username == username))
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found.",
        )
    return user


@router.post(
    "/entries",
    response_model=VaultEntryResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Store a new encrypted vault entry.",
)
async def create_vault_entry(
    payload: VaultEntryCreate,
    current_username: CurrentUser,
    db: DB,
) -> VaultEntryResponse:
    """
    Accept and store an encrypted vault entry.

    The client has:
    1. Derived enc_key locally from the master password (enc_key never leaves
       the client).
    2. Serialised the vault entry to JSON and encrypted it with AES-256-GCM.
    3. Sent only the ciphertext (including GCM tag) and nonce.

    The server stores exactly what it receives — opaque ciphertext.
    It cannot read, modify, or forge vault entries.
    """
    user = await _get_user_or_404(current_username, db)

    entry = VaultEntry(
        user_id=user.id,
        ciphertext_hex=payload.ciphertext_hex,
        nonce_hex=payload.nonce_hex,
    )
    db.add(entry)
    await db.flush()

    return VaultEntryResponse(
        id=entry.id,
        ciphertext_hex=entry.ciphertext_hex,
        nonce_hex=entry.nonce_hex,
        created_at=entry.created_at.isoformat(),
    )


@router.get(
    "/entries",
    response_model=list[VaultEntryResponse],
    summary="Retrieve all encrypted vault entries for the authenticated user.",
)
async def list_vault_entries(
    current_username: CurrentUser,
    db: DB,
) -> list[VaultEntryResponse]:
    """
    Return all encrypted entries for the current user.

    The client will decrypt each entry locally using the derived enc_key.
    """
    user = await _get_user_or_404(current_username, db)

    result = await db.execute(
        select(VaultEntry)
        .where(VaultEntry.user_id == user.id)
        .order_by(VaultEntry.created_at.desc())
    )
    entries = result.scalars().all()

    return [
        VaultEntryResponse(
            id=e.id,
            ciphertext_hex=e.ciphertext_hex,
            nonce_hex=e.nonce_hex,
            created_at=e.created_at.isoformat(),
        )
        for e in entries
    ]


@router.delete(
    "/entries/{entry_id}",
    response_model=DeleteResponse,
    summary="Delete a vault entry by ID.",
)
async def delete_vault_entry(
    entry_id: int,
    current_username: CurrentUser,
    db: DB,
) -> DeleteResponse:
    """
    Delete a vault entry, enforcing ownership.

    A user can only delete their own entries.  The server verifies ownership
    by checking that the entry's user_id matches the authenticated user's id.
    This prevents horizontal privilege escalation.
    """
    user = await _get_user_or_404(current_username, db)

    entry = await db.scalar(
        select(VaultEntry).where(
            VaultEntry.id == entry_id,
            VaultEntry.user_id == user.id,  # ownership check
        )
    )
    if entry is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Vault entry not found.",
        )

    await db.delete(entry)
    return DeleteResponse()
