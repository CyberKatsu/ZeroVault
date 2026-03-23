"""
zerovault.crypto
~~~~~~~~~~~~~~~~
Public API for ZeroVault's cryptographic operations.

All encryption/decryption happens here — the backend imports only
``auth_key`` (for server-side hashing and verification) and never sees
raw key material or plaintext vault data.
"""

from crypto.auth_key import hash_auth_key, verify_auth_key
from crypto.kdf import derive_keys, derive_master_key, generate_salt
from crypto.vault import decrypt_vault_entry, encrypt_vault_entry, generate_nonce

__all__ = [
    "generate_salt",
    "derive_master_key",
    "derive_keys",
    "encrypt_vault_entry",
    "decrypt_vault_entry",
    "generate_nonce",
    "hash_auth_key",
    "verify_auth_key",
]
