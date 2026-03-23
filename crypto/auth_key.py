"""
crypto/auth_key.py
~~~~~~~~~~~~~~~~~~
Server-side handling of the authentication key.

Role in the protocol
────────────────────
The client derives ``auth_key`` (32 bytes) from the user's master password via
Argon2id + HKDF.  During registration or login the client transmits this value
(hex-encoded) to the FastAPI backend.  The server MUST NOT store auth_key in
plaintext — doing so would allow anyone with read access to the database to
replay that value and authenticate as the user.

Defence: bcrypt hashing
───────────────────────
Before persisting, the server runs ``hash_auth_key`` which bcrypt-hashes the
hex-encoded auth_key.  The bcrypt call:
  • Applies its own random 128-bit salt (different from the Argon2 salt).
  • Runs ``2^BCRYPT_ROUNDS`` iterations internally (≈ 4096 at rounds=12).
  • Returns an encoded string that includes the salt, so only the output of
    ``hash_auth_key`` needs to be stored — no separate bcrypt salt column.

Why bcrypt and not just SHA-256?
─────────────────────────────────
auth_key is a 256-bit random-looking value, so SHA-256(auth_key) would be
computationally trivial to re-compute for any stolen row.  bcrypt's work
factor makes each guess take ~0.3–0.5 s, neutralising bulk replay-lookup
attacks against a stolen credential database.

Why not a second Argon2 here?
──────────────────────────────
The client has already spent the expensive Argon2 budget (64 MiB, 3 passes).
Adding a second Argon2 round server-side would double user-visible latency for
no additional security against the primary threat (replay from stolen DB rows).
bcrypt at rounds=12 provides adequate protection for a high-entropy input
(auth_key is 256 bits, not a human-chosen password).
"""

import bcrypt

from crypto.constants import BCRYPT_ROUNDS


def hash_auth_key(auth_key: bytes) -> str:
    """Return the bcrypt hash of ``auth_key`` for server-side storage.

    The 32-byte auth_key is hex-encoded to a 64-character ASCII string before
    hashing.  This keeps the input well under bcrypt's 72-byte processing limit
    while remaining human-readable in debug contexts.

    Parameters
    ----------
    auth_key:
        Raw 32-byte authentication key derived by the client via HKDF.

    Returns
    -------
    str
        bcrypt-encoded hash string (60 characters).  Store this in the database.
        The string embeds the algorithm, cost factor, and salt, so no additional
        columns are required.
    """
    if not auth_key:
        raise ValueError("auth_key must not be empty")

    # Hex-encode: 32 bytes → 64-char ASCII string, comfortably under bcrypt's
    # 72-byte limit.  Using hex (not base64) avoids padding characters.
    hex_key: str = auth_key.hex()
    hashed: bytes = bcrypt.hashpw(hex_key.encode("ascii"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
    return hashed.decode("ascii")


def verify_auth_key(auth_key: bytes, stored_hash: str) -> bool:
    """Verify that ``auth_key`` matches the stored bcrypt hash.

    Uses ``bcrypt.checkpw`` which is timing-safe (constant-time comparison).
    Returns ``False`` rather than raising on mismatch so callers can produce a
    consistent HTTP 401 without leaking stack-trace information.

    Parameters
    ----------
    auth_key:
        Raw 32-byte authentication key submitted by the client.
    stored_hash:
        The string previously returned by ``hash_auth_key`` (from the DB row).

    Returns
    -------
    bool
        ``True`` if and only if auth_key matches the stored hash.
    """
    if not auth_key or not stored_hash:
        return False

    hex_key: str = auth_key.hex()
    try:
        return bcrypt.checkpw(hex_key.encode("ascii"), stored_hash.encode("ascii"))
    except Exception:
        # bcrypt.checkpw raises on malformed hashes; treat as failed verification
        return False
