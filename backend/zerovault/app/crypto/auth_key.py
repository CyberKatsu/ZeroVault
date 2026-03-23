"""
zerovault.crypto.auth_key
=========================
Server-side bcrypt hashing and verification of the authentication key.

Why bcrypt here, when Argon2id already ran on the client?
----------------------------------------------------------
One might argue: "The auth_key is already the output of Argon2id — it has
256 bits of entropy.  Storing it in plaintext would be fine."

That argument is tempting but wrong for the following reasons:

1. DEFENCE IN DEPTH — if a breach exposes the raw auth_key (e.g. via a
   memory dump of a running process, a logging mistake, or a future
   vulnerability in the server code), bcrypt ensures the adversary still
   cannot impersonate users without the original master password.

2. INDUSTRY CONVENTION — password fields (even derived ones) in a database
   are expected to be hashed.  Security auditors and penetration testers
   will flag any "password" field stored as plaintext or in a reversible
   encoding.

3. ADDITIONAL BRUTE-FORCE RESISTANCE — bcrypt's work factor further slows
   an adversary attempting to verify candidate auth_keys against a stolen
   hash.  Combined with the client-side Argon2id, the attacker faces a
   two-layer KDF: Argon2id (memory-hard, on client) → bcrypt (time-hard,
   on server).

bcrypt truncation note
-----------------------
bcrypt has a maximum input length of 72 bytes.  Our auth_key is 32 bytes,
well within this limit, so no pre-hashing is needed.
"""

import bcrypt


def hash_auth_key(auth_key: bytes) -> str:
    """
    Hash an auth_key with bcrypt and return the hash as a UTF-8 string.

    Parameters
    ----------
    auth_key : bytes
        32-byte authentication key derived on the client.

    Returns
    -------
    str
        bcrypt hash string (60 chars, includes salt and work factor).

    Notes
    -----
    Work factor 12 → ≈ 250 ms on a 2024 server CPU.  This is acceptable
    for a login endpoint (called once per session) and imposes significant
    cost on an adversary running offline cracking.  Factor 10 (≈ 65 ms)
    would be too fast; factor 14 (≈ 1 s) may cause user-perceptible latency.
    """
    work_factor: int = 12
    salt: bytes = bcrypt.gensalt(rounds=work_factor)
    hashed: bytes = bcrypt.hashpw(auth_key, salt)
    return hashed.decode("utf-8")


def verify_auth_key(auth_key: bytes, stored_hash: str) -> bool:
    """
    Verify an auth_key against a stored bcrypt hash in constant time.

    bcrypt.checkpw uses a constant-time comparison internally, preventing
    timing side-channel attacks that could reveal information about the
    correct hash character-by-character.

    Parameters
    ----------
    auth_key : bytes
        Candidate auth_key supplied by the client at login.
    stored_hash : str
        The bcrypt hash stored in the database.

    Returns
    -------
    bool
        True if auth_key matches the stored hash, False otherwise.
    """
    return bcrypt.checkpw(auth_key, stored_hash.encode("utf-8"))
