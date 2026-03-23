"""
zerovault.crypto.vault_cipher
=============================
AES-256-GCM authenticated encryption for vault entries.

Why AES-256-GCM?
----------------
Vault entries must satisfy two security properties:

1. CONFIDENTIALITY  — the server must not be able to read plaintext.
2. INTEGRITY        — the server must not be able to silently modify ciphertext.
                      (A compromised server might attempt to feed tampered entries
                      to the client, e.g. substituting a known plaintext to
                      learn something about the key.)

Unauthenticated encryption (e.g. AES-CBC without a MAC) satisfies (1) but not
(2).  An adversary who can modify stored ciphertext could mount a padding-oracle
or chosen-ciphertext attack.

AES-GCM is an Authenticated Encryption with Associated Data (AEAD) scheme.  It
computes a 128-bit authentication tag over the ciphertext.  If a single bit of
the stored ciphertext or tag is modified, decryption raises an exception rather
than returning garbled plaintext.  This gives us both properties.

Nonce handling
--------------
GCM security REQUIRES that (key, nonce) pairs are never reused.  Nonce reuse
allows an adversary to recover the XOR of two plaintexts and compromises the
authentication guarantee entirely.

We generate nonces with os.urandom(12), giving 96 random bits.  Under the
birthday paradox, the collision probability is negligible for any realistic
number of vault entries (< 2^32).  We store the nonce alongside the ciphertext
so that decryption is possible without any additional state.

What the server stores
-----------------------
The server (FastAPI + PostgreSQL) receives and stores:
    - ciphertext   (variable length bytes)
    - nonce        (12 bytes)

The authentication tag is appended to the ciphertext by the AESGCM primitive
and extracted on decryption — callers do not handle it separately.

The server CANNOT:
    - Decrypt the ciphertext (enc_key never transmitted).
    - Forge a valid ciphertext (requires enc_key to produce a valid tag).
    - Silently modify ciphertext (any modification invalidates the tag).
"""

import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zerovault.app.crypto.constants import AES_KEY_LENGTH, GCM_TAG_LENGTH, NONCE_LENGTH


@dataclass(frozen=True)
class VaultCiphertext:
    """
    Wire representation of an encrypted vault entry.

    Attributes
    ----------
    ciphertext : bytes
        AES-256-GCM ciphertext including the appended 16-byte auth tag.
        Layout: [ciphertext bytes][16-byte GCM tag]
    nonce : bytes
        12-byte random nonce used during encryption.  Must be stored alongside
        the ciphertext and provided during decryption.
    """

    ciphertext: bytes
    nonce: bytes

    def to_hex_dict(self) -> dict[str, str]:
        """Serialise to hex strings suitable for JSON transport."""
        return {
            "ciphertext": self.ciphertext.hex(),
            "nonce": self.nonce.hex(),
        }

    @classmethod
    def from_hex_dict(cls, data: dict[str, str]) -> "VaultCiphertext":
        """Deserialise from hex strings received from the server."""
        return cls(
            ciphertext=bytes.fromhex(data["ciphertext"]),
            nonce=bytes.fromhex(data["nonce"]),
        )


def encrypt_entry(
    enc_key: bytes,
    plaintext_dict: dict[str, Any],
) -> VaultCiphertext:
    """
    Encrypt a vault entry dict with AES-256-GCM.

    The plaintext dict is serialised to UTF-8 JSON before encryption.  This
    ensures a canonical, deterministic byte representation.

    Parameters
    ----------
    enc_key : bytes
        32-byte AES-256 encryption key derived locally; NEVER transmitted to
        the server.
    plaintext_dict : dict
        Vault entry fields: e.g. {"site": "...", "username": "...",
        "password": "...", "notes": "..."}.

    Returns
    -------
    VaultCiphertext
        Frozen dataclass with ciphertext (including auth tag) and nonce.

    Raises
    ------
    ValueError
        If enc_key is not exactly AES_KEY_LENGTH bytes.
    """
    if len(enc_key) != AES_KEY_LENGTH:
        raise ValueError(
            f"enc_key must be {AES_KEY_LENGTH} bytes, got {len(enc_key)}."
        )

    # Serialise plaintext.  sort_keys for determinism (aids testing).
    plaintext_bytes: bytes = json.dumps(plaintext_dict, sort_keys=True).encode("utf-8")

    # Generate a fresh random nonce for every encryption operation.
    # NEVER reuse a nonce with the same key — GCM provides no security
    # guarantees if (key, nonce) is reused even once.
    nonce: bytes = os.urandom(NONCE_LENGTH)

    # AESGCM.encrypt returns ciphertext || tag (tag appended).
    # No associated data (aad=None) — we rely entirely on key secrecy for
    # access control, not on AAD binding.
    aesgcm = AESGCM(enc_key)
    # aad (associated data) is the third positional argument — pass None explicitly.
    # Using None means no associated data; authentication covers only ciphertext.
    ciphertext_with_tag: bytes = aesgcm.encrypt(nonce, plaintext_bytes, None)

    # Sanity-check that the tag is present (ciphertext must be longer than
    # plaintext by exactly GCM_TAG_LENGTH bytes).
    assert len(ciphertext_with_tag) == len(plaintext_bytes) + GCM_TAG_LENGTH

    return VaultCiphertext(ciphertext=ciphertext_with_tag, nonce=nonce)


def decrypt_entry(
    enc_key: bytes,
    vault_ciphertext: VaultCiphertext,
) -> dict[str, Any]:
    """
    Decrypt and authenticate a vault entry.

    Decryption verifies the GCM authentication tag BEFORE returning plaintext.
    If the ciphertext has been modified in any way, InvalidTag is raised and
    no plaintext is returned.

    Parameters
    ----------
    enc_key : bytes
        32-byte encryption key, derived locally from the master password.
    vault_ciphertext : VaultCiphertext
        The encrypted blob as stored/returned by the server.

    Returns
    -------
    dict
        The decrypted vault entry as a Python dict.

    Raises
    ------
    ValueError
        If enc_key length is wrong or nonce length is wrong.
    cryptography.exceptions.InvalidTag
        If authentication fails — ciphertext has been tampered with, or the
        wrong key was used.
    json.JSONDecodeError
        If the decrypted bytes are not valid JSON (should not happen if the
        entry was encrypted by encrypt_entry).
    """
    if len(enc_key) != AES_KEY_LENGTH:
        raise ValueError(
            f"enc_key must be {AES_KEY_LENGTH} bytes, got {len(enc_key)}."
        )
    if len(vault_ciphertext.nonce) != NONCE_LENGTH:
        raise ValueError(
            f"Nonce must be {NONCE_LENGTH} bytes, got {len(vault_ciphertext.nonce)}."
        )

    aesgcm = AESGCM(enc_key)

    # AESGCM.decrypt raises InvalidTag automatically if auth fails.
    # aad=None means no associated data was used during encryption.
    plaintext_bytes: bytes = aesgcm.decrypt(
        vault_ciphertext.nonce,
        vault_ciphertext.ciphertext,
        None,
    )

    return json.loads(plaintext_bytes.decode("utf-8"))
