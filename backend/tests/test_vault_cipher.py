"""
tests/test_vault_cipher.py
==========================
Tests for AES-256-GCM vault encryption and decryption.

What we verify
--------------
1. Round-trip: encrypt then decrypt returns original plaintext.
2. Nonce uniqueness: two encryptions of the same plaintext produce different
   nonces and different ciphertexts (probabilistic encryption).
3. Tamper detection: modifying the ciphertext raises InvalidTag.
4. Tamper detection: modifying the nonce raises InvalidTag.
5. Wrong key: decrypting with a different key raises InvalidTag.
6. Key length enforcement: wrong key sizes are rejected.
7. VaultCiphertext hex serialisation round-trip.
"""

from __future__ import annotations

import os

import pytest
from cryptography.exceptions import InvalidTag

from zerovault.app.crypto.vault_cipher import (
    VaultCiphertext,
    decrypt_entry,
    encrypt_entry,
)
from zerovault.app.crypto.constants import AES_KEY_LENGTH, NONCE_LENGTH, GCM_TAG_LENGTH

SAMPLE_ENTRY: dict = {
    "site": "https://example.com",
    "username": "alice@example.com",
    "password": "S3cur3P@ssw0rd!",
    "notes": "Main work account",
}


def make_key() -> bytes:
    """Return a cryptographically random 32-byte AES key."""
    return os.urandom(AES_KEY_LENGTH)


# ── Round-trip ────────────────────────────────────────────────────────────────

def test_encrypt_decrypt_round_trip():
    """Decrypt(Encrypt(plaintext)) must return the original plaintext."""
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)
    recovered = decrypt_entry(key, ct)
    assert recovered == SAMPLE_ENTRY


def test_round_trip_preserves_all_fields():
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)
    recovered = decrypt_entry(key, ct)
    for field in ("site", "username", "password", "notes"):
        assert recovered[field] == SAMPLE_ENTRY[field]


def test_round_trip_empty_notes():
    key = make_key()
    entry = {**SAMPLE_ENTRY, "notes": ""}
    ct = encrypt_entry(key, entry)
    assert decrypt_entry(key, ct) == entry


def test_round_trip_unicode_password():
    """Non-ASCII passwords (e.g. Japanese) must survive the round-trip."""
    key = make_key()
    entry = {**SAMPLE_ENTRY, "password": "パスワード🔐"}
    ct = encrypt_entry(key, entry)
    assert decrypt_entry(key, ct) == entry


# ── Probabilistic encryption (nonce uniqueness) ───────────────────────────────

def test_same_plaintext_produces_different_ciphertext():
    """
    Two encryptions of identical plaintext must yield different nonces and
    ciphertexts.  Deterministic encryption would leak whether two entries have
    the same plaintext.
    """
    key = make_key()
    ct1 = encrypt_entry(key, SAMPLE_ENTRY)
    ct2 = encrypt_entry(key, SAMPLE_ENTRY)

    assert ct1.nonce != ct2.nonce, "Nonces must be unique per encryption"
    assert ct1.ciphertext != ct2.ciphertext


# ── Structural checks ─────────────────────────────────────────────────────────

def test_nonce_length():
    ct = encrypt_entry(make_key(), SAMPLE_ENTRY)
    assert len(ct.nonce) == NONCE_LENGTH


def test_ciphertext_length_includes_tag():
    """
    AES-GCM appends a 16-byte authentication tag to the ciphertext.
    The ciphertext should be longer than the serialised plaintext by exactly
    GCM_TAG_LENGTH bytes.
    """
    import json
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)
    plaintext_len = len(json.dumps(SAMPLE_ENTRY, sort_keys=True).encode("utf-8"))
    assert len(ct.ciphertext) == plaintext_len + GCM_TAG_LENGTH


# ── Tamper detection ──────────────────────────────────────────────────────────

def test_modified_ciphertext_raises_invalid_tag():
    """
    Any single-byte flip in the ciphertext must cause decryption to fail.
    This verifies that the GCM authentication tag is being checked.
    """
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)

    # Flip the first byte of the ciphertext
    tampered_bytes = bytes([ct.ciphertext[0] ^ 0xFF]) + ct.ciphertext[1:]
    tampered = VaultCiphertext(ciphertext=tampered_bytes, nonce=ct.nonce)

    with pytest.raises(InvalidTag):
        decrypt_entry(key, tampered)


def test_modified_tag_raises_invalid_tag():
    """Flipping a byte in the authentication tag (last 16 bytes) must fail."""
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)

    # Flip the last byte (part of the GCM tag)
    tampered_bytes = ct.ciphertext[:-1] + bytes([ct.ciphertext[-1] ^ 0xFF])
    tampered = VaultCiphertext(ciphertext=tampered_bytes, nonce=ct.nonce)

    with pytest.raises(InvalidTag):
        decrypt_entry(key, tampered)


def test_modified_nonce_raises_invalid_tag():
    """
    Swapping the nonce while keeping the ciphertext must fail authentication.
    This is the 'nonce misuse' scenario — the GCM tag was computed with the
    original nonce, so a different nonce produces an authentication failure.
    """
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)

    wrong_nonce = os.urandom(NONCE_LENGTH)
    tampered = VaultCiphertext(ciphertext=ct.ciphertext, nonce=wrong_nonce)

    with pytest.raises(InvalidTag):
        decrypt_entry(key, tampered)


def test_wrong_key_raises_invalid_tag():
    """
    Decrypting with a different key must fail.
    This is the server-operator threat: the server has the ciphertext but
    not enc_key, so it cannot decrypt.
    """
    key = make_key()
    wrong_key = make_key()
    assert key != wrong_key

    ct = encrypt_entry(key, SAMPLE_ENTRY)

    with pytest.raises(InvalidTag):
        decrypt_entry(wrong_key, ct)


# ── Input validation ──────────────────────────────────────────────────────────

def test_encrypt_wrong_key_length_raises():
    with pytest.raises(ValueError, match="enc_key must be"):
        encrypt_entry(b"tooshort", SAMPLE_ENTRY)


def test_decrypt_wrong_key_length_raises():
    ct = encrypt_entry(make_key(), SAMPLE_ENTRY)
    with pytest.raises(ValueError, match="enc_key must be"):
        decrypt_entry(b"tooshort", ct)


def test_decrypt_wrong_nonce_length_raises():
    key = make_key()
    ct = encrypt_entry(key, SAMPLE_ENTRY)
    bad = VaultCiphertext(ciphertext=ct.ciphertext, nonce=b"tooshort")
    with pytest.raises(ValueError, match="Nonce must be"):
        decrypt_entry(key, bad)


# ── Hex serialisation ─────────────────────────────────────────────────────────

def test_hex_dict_round_trip():
    """VaultCiphertext → hex dict → VaultCiphertext must be lossless."""
    ct = encrypt_entry(make_key(), SAMPLE_ENTRY)
    d = ct.to_hex_dict()
    restored = VaultCiphertext.from_hex_dict(d)
    assert restored.ciphertext == ct.ciphertext
    assert restored.nonce == ct.nonce


def test_hex_dict_contains_expected_keys():
    ct = encrypt_entry(make_key(), SAMPLE_ENTRY)
    d = ct.to_hex_dict()
    assert set(d.keys()) == {"ciphertext", "nonce"}


def test_hex_dict_values_are_hex_strings():
    ct = encrypt_entry(make_key(), SAMPLE_ENTRY)
    d = ct.to_hex_dict()
    # Should be valid hex strings (no exception)
    bytes.fromhex(d["ciphertext"])
    bytes.fromhex(d["nonce"])
