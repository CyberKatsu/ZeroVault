"""
zerovault.models
================
SQLAlchemy 2.0 ORM models using the async DeclarativeBase.

Table design: what is stored vs. what is NOT
---------------------------------------------

users table:
  ✓ username                  (unique identifier)
  ✓ auth_key_hash             (bcrypt hash of HKDF-derived auth_key)
  ✓ argon2_salt               (hex; needed by client to re-derive auth_key at login)
  ✓ argon2_time_cost          (KDF parameter)
  ✓ argon2_memory_cost_kib    (KDF parameter)
  ✓ argon2_parallelism        (KDF parameter)
  ✗ master_password           (never stored, never transmitted)
  ✗ enc_key                   (never stored, never transmitted)
  ✗ auth_key plaintext        (only bcrypt hash stored)

vault_entries table:
  ✓ ciphertext                (AES-256-GCM output including tag)
  ✓ nonce                     (12-byte GCM nonce)
  ✓ user_id                   (foreign key)
  ✗ site, username, password  (never stored — only as encrypted ciphertext)
  ✗ enc_key                   (never stored, never reaches server)
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"

    # Integer maps to INTEGER on SQLite (required for autoincrement) and
    # to INTEGER on PostgreSQL.  BigInteger is not needed here — int4 range
    # (2.1 billion) is ample for a password manager.
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    username: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )
    # bcrypt hash of the HKDF-derived authentication key.
    # 60 characters for standard bcrypt output.
    auth_key_hash: Mapped[str] = mapped_column(String(60), nullable=False)

    # Argon2id KDF parameters — stored so the client can re-derive auth_key
    # at login without having to trust parameters sent by the client at login
    # time (which could be downgrade attacks).
    argon2_salt: Mapped[str] = mapped_column(
        String(64), nullable=False, comment="64-char hex (32 bytes)"
    )
    argon2_time_cost: Mapped[int] = mapped_column(Integer, nullable=False)
    argon2_memory_cost_kib: Mapped[int] = mapped_column(Integer, nullable=False)
    argon2_parallelism: Mapped[int] = mapped_column(Integer, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    vault_entries: Mapped[list[VaultEntry]] = relationship(
        "VaultEntry",
        back_populates="owner",
        cascade="all, delete-orphan",
        lazy="select",
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} username={self.username!r}>"


class VaultEntry(Base):
    __tablename__ = "vault_entries"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # AES-256-GCM ciphertext + tag (AESGCM appends tag to ciphertext).
    # Stored as hex TEXT rather than BYTEA for portability; decode at use.
    ciphertext_hex: Mapped[str] = mapped_column(Text, nullable=False)

    # 12-byte GCM nonce, hex-encoded (24 chars).
    nonce_hex: Mapped[str] = mapped_column(String(24), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )

    owner: Mapped[User] = relationship("User", back_populates="vault_entries")

    def __repr__(self) -> str:
        return f"<VaultEntry id={self.id} user_id={self.user_id}>"
