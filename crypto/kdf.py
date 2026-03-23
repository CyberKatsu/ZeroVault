"""
crypto/kdf.py
~~~~~~~~~~~~~
Key derivation for ZeroVault.

Stage 1 — Argon2id (``derive_master_key``)
    Converts a human-memorable master password + per-user random salt into a
    high-entropy 512-bit master key.  Argon2id's memory-hardness means an
    attacker with a database of stolen salts cannot brute-force common passwords
    cheaply on a GPU farm.

Stage 2 — HKDF (``derive_keys``)
    Splits the 512-bit master key into *two independent* 256-bit keys using
    HKDF-SHA256 with domain-separation labels:

        encryption_key  (never leaves the client process)
        auth_key        (sent to the server *once* per login, then discarded)

    Why two keys instead of one?
    ────────────────────────────
    If the same key were used for both encryption AND authentication:
      • The server would receive the key during login.
      • A compromised server could decrypt every vault entry.

    By deriving two independent keys from the master key using distinct HKDF
    info labels, the encryption key and auth key are cryptographically
    unrelated: knowing one reveals nothing about the other.  The server
    *never* sees or stores the encryption key.

    See CRYPTOGRAPHY.md for the full threat-model analysis.
"""

import secrets

from argon2.low_level import hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from crypto.constants import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST,
    ARGON2_PARALLELISM,
    ARGON2_SALT_LENGTH,
    ARGON2_TIME_COST,
    ARGON2_TYPE,
    DERIVED_KEY_LENGTH,
    HKDF_INFO_AUTH,
    HKDF_INFO_ENCRYPTION,
)


# ── Public helpers ─────────────────────────────────────────────────────────────

def generate_salt() -> bytes:
    """Return a cryptographically random salt for Argon2.

    Uses ``secrets.token_bytes`` which reads from the OS CSPRNG
    (``/dev/urandom`` on Linux/macOS, ``CryptGenRandom`` on Windows).
    We deliberately do NOT use ``random.randbytes`` — ``random`` is a
    pseudo-random generator seeded from system time and is NOT suitable for
    cryptographic use.

    Returns
    -------
    bytes
        ``ARGON2_SALT_LENGTH`` random bytes (16 by default, 128 bits).
    """
    return secrets.token_bytes(ARGON2_SALT_LENGTH)


def derive_master_key(
    password: str,
    salt: bytes,
    *,
    time_cost: int = ARGON2_TIME_COST,
    memory_cost: int = ARGON2_MEMORY_COST,
    parallelism: int = ARGON2_PARALLELISM,
) -> bytes:
    """Derive a 512-bit master key from ``password`` + ``salt`` using Argon2id.

    We call ``argon2.low_level.hash_secret_raw`` directly rather than the
    high-level ``PasswordHasher`` API because:
      • We need *raw bytes* as input to HKDF, not the encoded PHC string.
      • We control every parameter explicitly — no "recommended defaults"
        hiding underneath abstraction layers that may change between releases.

    Parameters
    ----------
    password:
        The user's master password as a UTF-8 string.
    salt:
        Per-user random bytes (``ARGON2_SALT_LENGTH`` bytes).
    time_cost, memory_cost, parallelism:
        Argon2 parameters; default to the module-level constants but can be
        overridden at call time (e.g. to replay an old key from stored params).

    Returns
    -------
    bytes
        ``ARGON2_HASH_LENGTH`` bytes (64 by default, 512 bits) of key material.

    Notes
    -----
    The returned bytes are NOT suitable for direct use — pass them to
    ``derive_keys`` to obtain separate encryption and authentication keys.
    """
    if not password:
        raise ValueError("master password must not be empty")
    if len(salt) < 8:  # Argon2 minimum salt length
        raise ValueError(f"salt must be at least 8 bytes, got {len(salt)}")

    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_cost,
        parallelism=parallelism,
        hash_len=ARGON2_HASH_LENGTH,
        type=ARGON2_TYPE,
    )


def derive_keys(master_key: bytes) -> tuple[bytes, bytes]:
    """Split ``master_key`` into ``(encryption_key, auth_key)`` via HKDF-SHA256.

    HKDF (RFC 5869) is an Extract-and-Expand key derivation function built on
    HMAC.  By passing different ``info`` labels to two separate HKDF instances
    (both sharing the same IKM), we obtain outputs that are:
      • Independent: knowledge of one key gives zero information about the other.
      • Deterministic: same master_key always produces the same pair of keys,
        which is required so the user can decrypt their vault after re-deriving
        on the next login.

    Parameters
    ----------
    master_key:
        Raw output of ``derive_master_key`` (must be ``ARGON2_HASH_LENGTH``
        bytes).

    Returns
    -------
    tuple[bytes, bytes]
        ``(encryption_key, auth_key)`` — each ``DERIVED_KEY_LENGTH`` bytes
        (32 bytes, 256 bits).

        encryption_key: used for AES-256-GCM vault encryption.
                        MUST NEVER be transmitted to the server.

        auth_key:       sent to the server once per login/register as the
                        effective "password hash input".  The server stores
                        bcrypt(auth_key), never auth_key itself.
    """
    if len(master_key) < DERIVED_KEY_LENGTH:
        raise ValueError(
            f"master_key is too short ({len(master_key)} bytes); "
            f"expected at least {DERIVED_KEY_LENGTH} bytes"
        )

    encryption_key = _hkdf_derive(master_key, HKDF_INFO_ENCRYPTION)
    auth_key = _hkdf_derive(master_key, HKDF_INFO_AUTH)
    return encryption_key, auth_key


# ── Private helpers ────────────────────────────────────────────────────────────

def _hkdf_derive(ikm: bytes, info: bytes) -> bytes:
    """Run one HKDF-SHA256 Expand step.

    We do NOT supply an HKDF salt here: the entropy is already high (512-bit
    Argon2 output) so the Extract step would add nothing.  The ``info``
    parameter provides domain separation.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=None,   # IKM is already uniformly random; no Extract needed
        info=info,
    )
    return hkdf.derive(ikm)
