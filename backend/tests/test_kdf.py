"""
tests/test_kdf.py
=================
Tests for the two-key derivation pattern.

What we verify
--------------
1. derive_keys returns a KDFResult with enc_key and auth_key of correct length.
2. Determinism: same (password, salt) always produces the same keys.
3. Independence: enc_key ≠ auth_key (HKDF domain separation working).
4. Salt sensitivity: different salts produce different key material.
5. Password sensitivity: different passwords produce different key material.
6. Salt length enforcement: short salts are rejected.
7. generate_salt produces unique values (CSPRNG, not PRNG).
"""

from __future__ import annotations

import pytest

from zerovault.app.crypto.kdf import KDFResult, derive_keys, generate_salt
from zerovault.app.crypto.constants import AES_KEY_LENGTH, SALT_LENGTH

# Use minimal Argon2 parameters so tests complete in milliseconds.
# We patch the module-level constants via monkeypatching.
import zerovault.app.crypto.kdf as kdf_module
import zerovault.app.crypto.constants as constants_module


@pytest.fixture(autouse=True)
def fast_argon2(monkeypatch):
    """Override Argon2 parameters globally for the test module."""
    monkeypatch.setattr(constants_module, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(constants_module, "ARGON2_MEMORY_COST_KIB", 8)
    monkeypatch.setattr(constants_module, "ARGON2_PARALLELISM", 1)


def _derive(password: str = "master_pass", salt: bytes | None = None) -> KDFResult:
    if salt is None:
        salt = generate_salt()
    return derive_keys(password.encode("utf-8"), salt)


# ── Key length ────────────────────────────────────────────────────────────────

def test_enc_key_length():
    result = _derive()
    assert len(result.enc_key) == AES_KEY_LENGTH, (
        f"enc_key must be {AES_KEY_LENGTH} bytes, got {len(result.enc_key)}"
    )


def test_auth_key_length():
    result = _derive()
    assert len(result.auth_key) == AES_KEY_LENGTH


# ── Determinism ───────────────────────────────────────────────────────────────

def test_derive_keys_is_deterministic():
    """Same (password, salt) must always yield identical keys."""
    salt = generate_salt()
    r1 = derive_keys(b"password123", salt)
    r2 = derive_keys(b"password123", salt)
    assert r1.enc_key == r2.enc_key, "enc_key must be deterministic"
    assert r1.auth_key == r2.auth_key, "auth_key must be deterministic"


# ── Domain separation (enc_key ≠ auth_key) ───────────────────────────────────

def test_enc_key_and_auth_key_are_distinct():
    """
    The two keys derived from the same master material must differ.
    If they were equal, using auth_key for server authentication would
    also expose enc_key.  HKDF's info parameter guarantees domain separation.
    """
    result = _derive()
    assert result.enc_key != result.auth_key, (
        "enc_key and auth_key must differ — HKDF domain separation failure"
    )


# ── Salt sensitivity ─────────────────────────────────────────────────────────

def test_different_salts_produce_different_keys():
    """Two users with the same password but different salts get different keys."""
    salt1 = generate_salt()
    salt2 = generate_salt()
    assert salt1 != salt2, "generate_salt should produce unique values"

    r1 = derive_keys(b"shared_password", salt1)
    r2 = derive_keys(b"shared_password", salt2)

    assert r1.enc_key != r2.enc_key
    assert r1.auth_key != r2.auth_key


# ── Password sensitivity ──────────────────────────────────────────────────────

def test_different_passwords_produce_different_keys():
    """Different passwords with the same salt must yield different keys."""
    salt = generate_salt()
    r1 = derive_keys(b"password_one", salt)
    r2 = derive_keys(b"password_two", salt)

    assert r1.enc_key != r2.enc_key
    assert r1.auth_key != r2.auth_key


# ── Input validation ──────────────────────────────────────────────────────────

def test_short_salt_raises_value_error():
    """Salts shorter than SALT_LENGTH bytes must be rejected."""
    short_salt = b"tooshort"
    with pytest.raises(ValueError, match="Salt must be at least"):
        derive_keys(b"password", short_salt)


def test_empty_password_raises_value_error():
    with pytest.raises(ValueError, match="must not be empty"):
        derive_keys(b"", generate_salt())


# ── generate_salt ─────────────────────────────────────────────────────────────

def test_generate_salt_length():
    salt = generate_salt()
    assert len(salt) == SALT_LENGTH


def test_generate_salt_uniqueness():
    """100 calls should produce 100 unique salts (CSPRNG, not seeded PRNG)."""
    salts = {generate_salt() for _ in range(100)}
    assert len(salts) == 100, "generate_salt produced a collision — CSPRNG failure"


# ── Salt stored in result ─────────────────────────────────────────────────────

def test_kdf_result_stores_salt():
    salt = generate_salt()
    result = derive_keys(b"password", salt)
    assert result.salt == salt
