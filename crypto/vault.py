"""
crypto/vault.py
~~~~~~~~~~~~~~~
AES-256-GCM authenticated encryption for ZeroVault vault entries.

Why AES-256-GCM?
────────────────
GCM (Galois/Counter Mode) is an AEAD (Authenticated Encryption with Associated
Data) construction.  "Authenticated" means every decryption call first verifies
a 128-bit authentication tag before revealing *any* plaintext bytes.  This
closes two important attack vectors:

  1. **Chosen-ciphertext attacks** — an attacker cannot craft ciphertext that
     decrypts to a useful value; the tag check catches any modification.
  2. **Bit-flipping attacks** — flipping a ciphertext bit changes the tag,
     so a network attacker cannot silently corrupt stored entries.

Implementation notes
────────────────────
• A fresh random 12-byte nonce is generated for *every* encryption operation.
  Nonce reuse under the same key with GCM is catastrophic: it leaks the
  authentication key and, in some cases, the plaintext.  We use
  ``secrets.token_bytes`` (OS CSPRNG) — never ``random``.

• The ``cryptography`` library's ``AESGCM`` class bundles the authentication
  tag into the ciphertext: the final 16 bytes of the returned blob are the tag.
  We store nonce and ciphertext (including tag) as separate Base64-encoded
  columns.

• Vault entries are JSON-serialised dictionaries so that any combination of
  fields (site, username, password, notes, TOTP seeds, …) can be encrypted
  as a single atomic unit with no partial-decryption side effects.

See CRYPTOGRAPHY.md §3 for a full explanation of the encryption pipeline.
"""

import json
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from crypto.constants import DERIVED_KEY_LENGTH, GCM_NONCE_LENGTH, GCM_TAG_LENGTH


# ── Public API ─────────────────────────────────────────────────────────────────

def generate_nonce() -> bytes:
    """Return a cryptographically random GCM nonce.

    12 bytes (96 bits) is the NIST-recommended nonce length for AES-GCM.
    Each call produces an independent random value from the OS CSPRNG.

    Returns
    -------
    bytes
        ``GCM_NONCE_LENGTH`` random bytes (12 by default).
    """
    return secrets.token_bytes(GCM_NONCE_LENGTH)


def encrypt_vault_entry(
    entry: dict[str, Any],
    encryption_key: bytes,
    *,
    nonce: bytes | None = None,
) -> tuple[bytes, bytes]:
    """Encrypt a vault entry dictionary using AES-256-GCM.

    The entry is first serialised to UTF-8 JSON (canonical field order,
    no trailing whitespace) and then encrypted.  Storing JSON means the
    ciphertext is self-describing: adding new entry fields in future
    versions does not require a schema migration.

    Parameters
    ----------
    entry:
        Plain-text vault entry.  Typical keys: ``site``, ``username``,
        ``password``, ``notes``.  Any JSON-serialisable dict is accepted.
    encryption_key:
        32-byte AES-256 key (output of ``derive_keys()[0]``).
    nonce:
        Optional override nonce.  If ``None`` (default), a fresh random
        12-byte nonce is generated.  Only supply a custom nonce in tests;
        never reuse nonces in production.

    Returns
    -------
    tuple[bytes, bytes]
        ``(nonce, ciphertext)`` where ``ciphertext`` is the encrypted JSON
        *including* the 16-byte GCM authentication tag appended at the end.

    Raises
    ------
    ValueError
        If ``encryption_key`` is not exactly ``DERIVED_KEY_LENGTH`` bytes.
    """
    _validate_key(encryption_key)

    plaintext: bytes = json.dumps(entry, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )
    nonce = nonce if nonce is not None else generate_nonce()

    aesgcm = AESGCM(encryption_key)
    # AESGCM.encrypt appends a GCM_TAG_LENGTH-byte authentication tag at the
    # end of the returned ciphertext.  We rely on this to verify integrity on
    # decryption — do NOT strip or truncate the returned bytes.
    ciphertext: bytes = aesgcm.encrypt(nonce, plaintext, aad=None)

    assert len(ciphertext) == len(plaintext) + GCM_TAG_LENGTH, (
        "AESGCM output length invariant violated — this is a library bug"
    )

    return nonce, ciphertext


def decrypt_vault_entry(
    nonce: bytes,
    ciphertext: bytes,
    encryption_key: bytes,
) -> dict[str, Any]:
    """Decrypt and authenticate a vault entry ciphertext.

    Decryption is atomic: the GCM authentication tag is verified *before* any
    plaintext bytes are returned.  If the tag check fails for any reason
    (wrong key, tampered ciphertext, wrong nonce, truncated blob), a
    ``cryptography.exceptions.InvalidTag`` exception is raised and no plaintext
    is produced.

    Parameters
    ----------
    nonce:
        The 12-byte nonce that was used during encryption (stored alongside the
        ciphertext in the database).
    ciphertext:
        The encrypted blob including the appended 16-byte GCM tag.
    encryption_key:
        32-byte AES-256 key (must be the *same* key used during encryption).

    Returns
    -------
    dict[str, Any]
        The original plain-text vault entry dictionary.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If the authentication tag verification fails.  This can mean:
          • Wrong encryption key
          • Tampered ciphertext (bit-flip, truncation, extension)
          • Wrong nonce
          • Corrupted database row
    json.JSONDecodeError
        If decryption succeeds but the result is not valid JSON (should never
        happen with a correct key and untampered ciphertext).
    ValueError
        If argument lengths are clearly invalid.
    """
    _validate_key(encryption_key)
    if len(nonce) != GCM_NONCE_LENGTH:
        raise ValueError(
            f"nonce must be {GCM_NONCE_LENGTH} bytes, got {len(nonce)}"
        )
    if len(ciphertext) < GCM_TAG_LENGTH:
        raise ValueError(
            f"ciphertext too short ({len(ciphertext)} bytes); minimum is {GCM_TAG_LENGTH}"
        )

    aesgcm = AESGCM(encryption_key)
    # decrypt raises cryptography.exceptions.InvalidTag if tag verification
    # fails.  We intentionally do NOT catch this — callers must handle it.
    plaintext: bytes = aesgcm.decrypt(nonce, ciphertext, aad=None)

    return json.loads(plaintext.decode("utf-8"))


# ── Private helpers ────────────────────────────────────────────────────────────

def _validate_key(key: bytes) -> None:
    """Raise ``ValueError`` if ``key`` is not the expected length."""
    if len(key) != DERIVED_KEY_LENGTH:
        raise ValueError(
            f"encryption_key must be {DERIVED_KEY_LENGTH} bytes (AES-256), "
            f"got {len(key)}"
        )
