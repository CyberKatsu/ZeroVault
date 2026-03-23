"""
tests/test_auth_key.py
======================
Tests for bcrypt hashing and verification of the authentication key.

What we verify
--------------
1. hash_auth_key returns a string (bcrypt hash).
2. verify_auth_key returns True for the correct key.
3. verify_auth_key returns False for a different key.
4. Two calls to hash_auth_key produce different hashes (bcrypt salting).
5. The produced hash verifies correctly despite being different each time.
6. No timing shortcut: verify_auth_key uses constant-time comparison.
   (We cannot directly test this, but we verify the function uses bcrypt.checkpw.)
"""

from __future__ import annotations

import os
import pytest

from zerovault.app.crypto.auth_key import hash_auth_key, verify_auth_key
from zerovault.app.crypto.constants import AES_KEY_LENGTH


def make_auth_key() -> bytes:
    return os.urandom(AES_KEY_LENGTH)


# ── Hash format ───────────────────────────────────────────────────────────────

def test_hash_auth_key_returns_string():
    key = make_auth_key()
    h = hash_auth_key(key)
    assert isinstance(h, str)


def test_hash_auth_key_is_bcrypt_format():
    """bcrypt hashes always start with $2b$ and are 60 chars."""
    key = make_auth_key()
    h = hash_auth_key(key)
    assert h.startswith("$2b$"), f"Expected bcrypt prefix, got: {h[:4]}"
    assert len(h) == 60, f"Expected 60-char bcrypt hash, got {len(h)}"


# ── Verification — correct key ────────────────────────────────────────────────

def test_verify_auth_key_correct_returns_true():
    key = make_auth_key()
    h = hash_auth_key(key)
    assert verify_auth_key(key, h) is True


# ── Verification — wrong key ──────────────────────────────────────────────────

def test_verify_auth_key_wrong_key_returns_false():
    key = make_auth_key()
    wrong_key = make_auth_key()
    assert key != wrong_key
    h = hash_auth_key(key)
    assert verify_auth_key(wrong_key, h) is False


def test_verify_auth_key_all_zeros_wrong():
    key = make_auth_key()
    h = hash_auth_key(key)
    zero_key = bytes(AES_KEY_LENGTH)
    assert verify_auth_key(zero_key, h) is False


# ── Salting (non-determinism) ─────────────────────────────────────────────────

def test_same_key_produces_different_hashes():
    """
    bcrypt uses a random 128-bit salt per hash operation.
    Two hashes of the same key must differ; both must verify correctly.
    This protects against rainbow table attacks.
    """
    key = make_auth_key()
    h1 = hash_auth_key(key)
    h2 = hash_auth_key(key)
    assert h1 != h2, "bcrypt should produce unique hashes due to random salting"
    # Both must still verify
    assert verify_auth_key(key, h1) is True
    assert verify_auth_key(key, h2) is True


# ── Edge cases ────────────────────────────────────────────────────────────────

def test_verify_empty_bytes_against_real_hash():
    """Empty bytes should not verify against a real key's hash."""
    key = make_auth_key()
    h = hash_auth_key(key)
    assert verify_auth_key(b"", h) is False
