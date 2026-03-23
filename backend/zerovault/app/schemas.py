"""
zerovault.schemas
=================
Pydantic v2 models for all API request/response bodies.

All fields are explicitly typed — no Any, no untyped Optional.
Sensitive fields (auth_key) are hex-encoded strings on the wire; the server
decodes them to bytes before use and never logs or returns them.
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


# ─── Registration ─────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    """Sent by client at registration time.

    The client has already run Argon2id and derived auth_key locally.
    The master password is NOT included — only the derived auth_key is sent.
    """

    username: str = Field(
        min_length=3,
        max_length=64,
        description="Unique username for the account.",
    )
    auth_key_hex: str = Field(
        description=(
            "64-character hex string representing the 32-byte HKDF-derived "
            "authentication key.  Never the master password."
        )
    )
    # KDF parameters are stored so that the client can re-derive keys on login
    # without the server having to trust the client's claimed parameters.
    argon2_salt_hex: str = Field(
        description="64-char hex (32-byte) random Argon2 salt generated at registration."
    )
    argon2_time_cost: int = Field(
        ge=1, le=20,
        description="Argon2 time cost (iterations).",
    )
    argon2_memory_cost_kib: int = Field(
        ge=8, le=2097152,          # 8 KiB (argon2-cffi minimum) – 2 GiB
        description="Argon2 memory cost in kibibytes.",
    )
    argon2_parallelism: int = Field(
        ge=1, le=16,
        description="Argon2 degree of parallelism.",
    )

    @field_validator("auth_key_hex")
    @classmethod
    def validate_auth_key_hex(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("auth_key_hex must be exactly 64 hex characters (32 bytes).")
        bytes.fromhex(v)  # raises ValueError if invalid hex
        return v

    @field_validator("argon2_salt_hex")
    @classmethod
    def validate_argon2_salt_hex(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("argon2_salt_hex must be exactly 64 hex characters (32 bytes).")
        bytes.fromhex(v)
        return v


class RegisterResponse(BaseModel):
    user_id: int
    username: str
    message: str = "Registration successful."


# ─── Login ────────────────────────────────────────────────────────────────────

class KDFParamsResponse(BaseModel):
    """Returned to the client BEFORE login so it can re-derive auth_key.

    This endpoint is unauthenticated.  Returning KDF params for a non-existent
    username must take the same amount of time as returning them for a real
    user to prevent user enumeration.
    """

    argon2_salt_hex: str
    argon2_time_cost: int
    argon2_memory_cost_kib: int
    argon2_parallelism: int


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    auth_key_hex: str = Field(description="Hex-encoded 32-byte auth_key.")

    @field_validator("auth_key_hex")
    @classmethod
    def validate_auth_key_hex(cls, v: str) -> str:
        if len(v) != 64:
            raise ValueError("auth_key_hex must be exactly 64 hex characters.")
        bytes.fromhex(v)
        return v


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ─── Vault entries ────────────────────────────────────────────────────────────

class VaultEntryCreate(BaseModel):
    """Client uploads an already-encrypted vault entry."""

    ciphertext_hex: str = Field(
        description=(
            "Hex-encoded AES-256-GCM ciphertext.  Includes the 16-byte "
            "authentication tag appended by the AESGCM primitive."
        )
    )
    nonce_hex: str = Field(
        description="Hex-encoded 12-byte GCM nonce used during encryption."
    )

    @field_validator("nonce_hex")
    @classmethod
    def validate_nonce_hex(cls, v: str) -> str:
        if len(v) != 24:
            raise ValueError("nonce_hex must be exactly 24 hex characters (12 bytes).")
        bytes.fromhex(v)
        return v

    @field_validator("ciphertext_hex")
    @classmethod
    def validate_ciphertext_hex(cls, v: str) -> str:
        # Minimum: 1 byte plaintext + 16 byte tag = 17 bytes = 34 hex chars
        if len(v) < 34:
            raise ValueError("ciphertext_hex too short to contain GCM tag.")
        if len(v) % 2 != 0:
            raise ValueError("ciphertext_hex must have even length.")
        bytes.fromhex(v)
        return v


class VaultEntryResponse(BaseModel):
    """Returned to the client.  Contains ONLY ciphertext — no plaintext."""

    id: int
    ciphertext_hex: str
    nonce_hex: str
    created_at: str

    model_config = {"from_attributes": True}


class DeleteResponse(BaseModel):
    message: str = "Entry deleted."


# ─── Generic error ────────────────────────────────────────────────────────────

class ErrorResponse(BaseModel):
    detail: str
