"""
zerovault.crypto
================
Zero-knowledge cryptographic primitives for ZeroVault.

Module layout
-------------
constants    – Argon2 parameters and domain labels (justified with comments).
kdf          – Master key derivation: Argon2id → HKDF → (enc_key, auth_key).
vault_cipher – AES-256-GCM encrypt / decrypt for vault entries.
auth_key     – bcrypt hashing and verification of the authentication key.

Design principle
----------------
Every module in this package operates on *bytes*, never on str representations
of sensitive material.  Callers are responsible for encoding/decoding for
transport (hex or base64).
"""
from zerovault.app.crypto.constants import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_HASH_LENGTH,
    AES_KEY_LENGTH,
    SALT_LENGTH,
    NONCE_LENGTH,
)
from zerovault.app.crypto.kdf import derive_keys, KDFResult
from zerovault.app.crypto.vault_cipher import encrypt_entry, decrypt_entry, VaultCiphertext
from zerovault.app.crypto.auth_key import hash_auth_key, verify_auth_key

__all__ = [
    # Constants
    "ARGON2_TIME_COST",
    "ARGON2_MEMORY_COST_KIB",
    "ARGON2_PARALLELISM",
    "ARGON2_HASH_LENGTH",
    "AES_KEY_LENGTH",
    "SALT_LENGTH",
    "NONCE_LENGTH",
    # KDF
    "derive_keys",
    "KDFResult",
    # Vault cipher
    "encrypt_entry",
    "decrypt_entry",
    "VaultCiphertext",
    # Auth key
    "hash_auth_key",
    "verify_auth_key",
]
