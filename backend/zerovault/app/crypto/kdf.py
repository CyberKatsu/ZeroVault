"""
zerovault.crypto.kdf
====================
Master key derivation using Argon2id and HKDF.

The Two-Key Derivation Pattern
-------------------------------
A naïve implementation would derive a single key from the master password and
use that key for BOTH vault encryption and server authentication.  This is
dangerous:

    THREAT: If the server stores verifiable evidence of the key (e.g. a bcrypt
    hash so it can authenticate the user), then a database breach exposes
    that bcrypt hash to offline cracking.  Once cracked, the adversary has
    the SAME key that encrypts the vault — the entire vault is compromised.

ZeroVault mitigates this by deriving two INDEPENDENT keys from the master
password using HKDF (with distinct info labels):

    master_password + salt
            │
         Argon2id          ← memory-hard KDF; slow per guess for attacker
            │
       master_key_material (64 bytes)
            │
           HKDF
           ├─── enc_key  (32 bytes, info="zerovault-v1-encryption-key")
           │        └── Used for AES-256-GCM vault encryption.
           │             NEVER transmitted to the server.
           └─── auth_key (32 bytes, info="zerovault-v1-authentication-key")
                    └── Sent to server during registration/login.
                         Server stores bcrypt(auth_key), never auth_key itself.

    RESULT: Even a full server breach (DB dump + bcrypt crack) gives the
    adversary auth_key but NOT enc_key.  The vault ciphertext remains secure
    because enc_key was never on the server.

Why HKDF and not simple slicing?
---------------------------------
Naively splitting the 64-byte Argon2 output as enc_key=first_32, auth_key=last_32
would work *in practice* (Argon2 output is pseudorandom), but HKDF provides:
  1. Formal domain separation via the `info` parameter.
  2. Independence: each output key is indistinguishable from random even if
     the extraction phase (Argon2) is partially biased.
  3. Extensibility: future keys (e.g. an HMAC signing key) can be added
     without changing the underlying KDF call.

Function signatures
--------------------
All inputs are bytes.  The caller is responsible for encoding/decoding for
transport.  No strings accepted to prevent accidental encoding bugs.
"""

import os
from dataclasses import dataclass

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from zerovault.app.crypto.constants import (
    ARGON2_HASH_LENGTH,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
    ARGON2_TIME_COST,
    AES_KEY_LENGTH,
    HKDF_INFO_AUTH_KEY,
    HKDF_INFO_ENC_KEY,
    SALT_LENGTH,
)


@dataclass(frozen=True)
class KDFResult:
    """
    Immutable result of a key derivation operation.

    Attributes
    ----------
    enc_key : bytes
        32-byte AES-256 encryption key.  **MUST NEVER be transmitted** to any
        server.  Store only in application memory for the duration of the
        session; zero out when done (Python does not guarantee secure erasure,
        but avoid unnecessary copies).
    auth_key : bytes
        32-byte authentication key.  This is what the client sends to the
        server as the effective password.  The server stores only
        bcrypt(auth_key).
    salt : bytes
        The random salt used during derivation.  For registration, this is
        freshly generated.  For login, it must be the salt retrieved from the
        server (stored at registration time).
    """

    enc_key: bytes
    auth_key: bytes
    salt: bytes


def generate_salt() -> bytes:
    """Return a cryptographically random salt of SALT_LENGTH bytes.

    Uses os.urandom, which on all supported platforms calls the OS CSPRNG
    (/dev/urandom on Linux, BCryptGenRandom on Windows).  We deliberately do
    NOT use the `random` module — it is a PRNG seeded with time and is
    wholly unsuitable for security-sensitive randomness.
    """
    return os.urandom(SALT_LENGTH)


def derive_keys(
    master_password: bytes,
    salt: bytes,
) -> KDFResult:
    """
    Derive enc_key and auth_key from a master password and salt.

    This is the core zero-knowledge KDF.  It is called on the CLIENT side:
    - During registration: with a freshly generated salt.
    - During login: with the salt retrieved from the server.

    The function is intentionally slow (≈ 65 ms on modern hardware at the
    default Argon2 parameters) to resist offline brute-force attacks.

    Parameters
    ----------
    master_password : bytes
        The user's master password, UTF-8 encoded by the caller.  We accept
        bytes to enforce that the caller has made an explicit encoding decision
        (UTF-8 recommended, NFC normalisation recommended for Unicode passwords).
    salt : bytes
        Random salt of at least SALT_LENGTH (32) bytes.

    Returns
    -------
    KDFResult
        Frozen dataclass containing enc_key, auth_key, and the salt.

    Raises
    ------
    ValueError
        If salt is shorter than SALT_LENGTH bytes.
    """
    if len(salt) < SALT_LENGTH:
        raise ValueError(
            f"Salt must be at least {SALT_LENGTH} bytes, got {len(salt)}."
        )
    if not master_password:
        raise ValueError("master_password must not be empty.")

    # ── Step 1: Argon2id — memory-hard key stretching ─────────────────────────
    # hash_secret_raw returns raw bytes (no encoding prefix), which is what we
    # need for HKDF input.  We use Type.ID for Argon2id.
    master_key_material: bytes = hash_secret_raw(
        secret=master_password,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Type.ID,
    )

    # ── Step 2: HKDF — domain-separated key expansion ─────────────────────────
    # We run HKDF twice with different `info` labels to produce two independent
    # keys.  The `salt` parameter of HKDF is separate from the Argon2 salt;
    # here we omit it (HKDF salt = None ≡ a string of HashLen zeros per RFC 5869),
    # which is acceptable because the master_key_material is already high-entropy
    # pseudorandom output from Argon2.
    enc_key: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=None,
        info=HKDF_INFO_ENC_KEY,
    ).derive(master_key_material)

    auth_key: bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_LENGTH,
        salt=None,
        info=HKDF_INFO_AUTH_KEY,
    ).derive(master_key_material)

    return KDFResult(enc_key=enc_key, auth_key=auth_key, salt=salt)
