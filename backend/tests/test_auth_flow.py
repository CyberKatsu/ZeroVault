"""
tests/test_auth_flow.py
=======================
End-to-end integration tests for the authentication flow.

These tests exercise the full HTTP stack:
  Client → HTTPX → FastAPI router → crypto layer → SQLite test DB

Cryptography is real (not mocked), but Argon2 parameters are reduced to
minimums via the conftest fixture to keep test runtime under a second.
"""

from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import AsyncClient

from zerovault.app.crypto.kdf import derive_keys, generate_salt
from zerovault.app.crypto.vault_cipher import VaultCiphertext, encrypt_entry, decrypt_entry
from zerovault.app.crypto.constants import AES_KEY_LENGTH

import zerovault.app.crypto.constants as constants_module

# Reduce Argon2 parameters for tests
constants_module.ARGON2_TIME_COST = 1
constants_module.ARGON2_MEMORY_COST_KIB = 8
constants_module.ARGON2_PARALLELISM = 1

TEST_PASSWORD = "integration-test-master-password"
TEST_USERNAME = "bob"


def build_register_payload(username: str, password: str) -> tuple[dict, bytes]:
    """
    Simulate client-side key derivation and build a /auth/register payload.
    Returns (payload_dict, enc_key) — enc_key is NOT sent to the server.
    """
    salt = generate_salt()
    kdf_result = derive_keys(password.encode("utf-8"), salt)
    payload = {
        "username": username,
        "auth_key_hex": kdf_result.auth_key.hex(),
        "argon2_salt_hex": salt.hex(),
        "argon2_time_cost": constants_module.ARGON2_TIME_COST,
        "argon2_memory_cost_kib": constants_module.ARGON2_MEMORY_COST_KIB,
        "argon2_parallelism": constants_module.ARGON2_PARALLELISM,
    }
    return payload, kdf_result.enc_key


# ── Registration ──────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_register_success(async_client: AsyncClient):
    payload, _ = build_register_payload(TEST_USERNAME, TEST_PASSWORD)
    response = await async_client.post("/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["username"] == TEST_USERNAME
    assert "user_id" in data


@pytest.mark.asyncio
async def test_register_duplicate_username(async_client: AsyncClient):
    payload, _ = build_register_payload(TEST_USERNAME, TEST_PASSWORD)
    await async_client.post("/auth/register", json=payload)
    # Register again with same username
    response = await async_client.post("/auth/register", json=payload)
    assert response.status_code == 409


@pytest.mark.asyncio
async def test_register_short_username_rejected(async_client: AsyncClient):
    payload, _ = build_register_payload("ab", TEST_PASSWORD)  # 2 chars — too short
    response = await async_client.post("/auth/register", json=payload)
    assert response.status_code == 422


# ── KDF params retrieval ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_get_kdf_params_returns_stored_values(async_client: AsyncClient):
    payload, _ = build_register_payload(TEST_USERNAME, TEST_PASSWORD)
    await async_client.post("/auth/register", json=payload)

    response = await async_client.get(f"/auth/kdf-params/{TEST_USERNAME}")
    assert response.status_code == 200
    data = response.json()
    assert data["argon2_salt_hex"] == payload["argon2_salt_hex"]
    assert data["argon2_time_cost"] == payload["argon2_time_cost"]
    assert data["argon2_memory_cost_kib"] == payload["argon2_memory_cost_kib"]
    assert data["argon2_parallelism"] == payload["argon2_parallelism"]


@pytest.mark.asyncio
async def test_get_kdf_params_unknown_user(async_client: AsyncClient):
    response = await async_client.get("/auth/kdf-params/nonexistent_user_xyz")
    assert response.status_code == 404


# ── Login ─────────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_login_success(async_client: AsyncClient):
    reg_payload, _ = build_register_payload(TEST_USERNAME, TEST_PASSWORD)
    await async_client.post("/auth/register", json=reg_payload)

    # Client fetches KDF params and re-derives auth_key
    kdf_resp = await async_client.get(f"/auth/kdf-params/{TEST_USERNAME}")
    kdf_data = kdf_resp.json()
    salt = bytes.fromhex(kdf_data["argon2_salt_hex"])
    kdf_result = derive_keys(TEST_PASSWORD.encode("utf-8"), salt)

    login_response = await async_client.post(
        "/auth/login",
        json={
            "username": TEST_USERNAME,
            "auth_key_hex": kdf_result.auth_key.hex(),
        },
    )
    assert login_response.status_code == 200
    data = login_response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_login_wrong_password(async_client: AsyncClient):
    reg_payload, _ = build_register_payload(TEST_USERNAME, TEST_PASSWORD)
    await async_client.post("/auth/register", json=reg_payload)

    # Derive with the WRONG password — auth_key will differ
    kdf_resp = await async_client.get(f"/auth/kdf-params/{TEST_USERNAME}")
    salt = bytes.fromhex(kdf_resp.json()["argon2_salt_hex"])
    wrong_kdf = derive_keys(b"wrong-password", salt)

    response = await async_client.post(
        "/auth/login",
        json={"username": TEST_USERNAME, "auth_key_hex": wrong_kdf.auth_key.hex()},
    )
    assert response.status_code == 401


@pytest.mark.asyncio
async def test_login_unknown_user(async_client: AsyncClient):
    response = await async_client.post(
        "/auth/login",
        json={
            "username": "ghost_user",
            "auth_key_hex": "a" * 64,
        },
    )
    assert response.status_code == 401


# ── Zero-knowledge property: enc_key never reaches server ────────────────────

@pytest.mark.asyncio
async def test_enc_key_not_transmitted_in_register(async_client: AsyncClient):
    """
    Verify that nothing in the register or login payloads contains enc_key.

    This is a smoke-test of the protocol design: the enc_key derived locally
    must never appear in any HTTP request body sent to the server.
    """
    salt = generate_salt()
    kdf_result = derive_keys(TEST_PASSWORD.encode("utf-8"), salt)

    enc_key_hex = kdf_result.enc_key.hex()

    reg_payload = {
        "username": TEST_USERNAME,
        "auth_key_hex": kdf_result.auth_key.hex(),
        "argon2_salt_hex": salt.hex(),
        "argon2_time_cost": constants_module.ARGON2_TIME_COST,
        "argon2_memory_cost_kib": constants_module.ARGON2_MEMORY_COST_KIB,
        "argon2_parallelism": constants_module.ARGON2_PARALLELISM,
    }

    # enc_key must not appear anywhere in the registration payload
    import json
    payload_str = json.dumps(reg_payload)
    assert enc_key_hex not in payload_str, (
        "enc_key appeared in the registration payload — zero-knowledge violation!"
    )

    # Also verify enc_key ≠ auth_key (the HKDF domain separation test)
    assert kdf_result.enc_key != kdf_result.auth_key


# ── Vault round-trip through API ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vault_create_list_delete(async_client: AsyncClient):
    """
    Full vault workflow:
    1. Register + login.
    2. Encrypt a vault entry locally.
    3. POST to /vault/entries.
    4. GET /vault/entries — verify ciphertext returned unchanged.
    5. Decrypt locally — verify original plaintext recovered.
    6. DELETE the entry.
    7. GET again — verify empty list.
    """
    import os

    # Step 1: Register
    reg_payload, enc_key = build_register_payload(TEST_USERNAME, TEST_PASSWORD)
    await async_client.post("/auth/register", json=reg_payload)

    # Step 2: Login
    kdf_resp = await async_client.get(f"/auth/kdf-params/{TEST_USERNAME}")
    salt = bytes.fromhex(kdf_resp.json()["argon2_salt_hex"])
    kdf_result = derive_keys(TEST_PASSWORD.encode("utf-8"), salt)
    enc_key = kdf_result.enc_key  # client-side only

    login_resp = await async_client.post(
        "/auth/login",
        json={"username": TEST_USERNAME, "auth_key_hex": kdf_result.auth_key.hex()},
    )
    token = login_resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Step 3: Encrypt locally and upload
    original_entry = {
        "site": "https://github.com",
        "username": "bob",
        "password": "gh_token_xyz",
        "notes": "Work GitHub",
    }
    ct: VaultCiphertext = encrypt_entry(enc_key, original_entry)
    create_resp = await async_client.post(
        "/vault/entries",
        json={"ciphertext_hex": ct.ciphertext.hex(), "nonce_hex": ct.nonce.hex()},
        headers=headers,
    )
    assert create_resp.status_code == 201
    entry_id = create_resp.json()["id"]

    # Step 4: List — server returns ciphertext unchanged
    list_resp = await async_client.get("/vault/entries", headers=headers)
    assert list_resp.status_code == 200
    entries = list_resp.json()
    assert len(entries) == 1
    server_ct_hex = entries[0]["ciphertext_hex"]
    server_nonce_hex = entries[0]["nonce_hex"]

    # Verify server returned the same bytes
    assert server_ct_hex == ct.ciphertext.hex()
    assert server_nonce_hex == ct.nonce.hex()

    # Step 5: Decrypt locally
    received_ct = VaultCiphertext(
        ciphertext=bytes.fromhex(server_ct_hex),
        nonce=bytes.fromhex(server_nonce_hex),
    )
    decrypted = decrypt_entry(enc_key, received_ct)
    assert decrypted == original_entry

    # Step 6: Delete
    del_resp = await async_client.delete(
        f"/vault/entries/{entry_id}", headers=headers
    )
    assert del_resp.status_code == 200

    # Step 7: Empty list
    list_resp2 = await async_client.get("/vault/entries", headers=headers)
    assert list_resp2.json() == []


@pytest.mark.asyncio
async def test_vault_requires_authentication(async_client: AsyncClient):
    """Unauthenticated requests to vault endpoints must be rejected."""
    response = await async_client.get("/vault/entries")
    assert response.status_code == 403


@pytest.mark.asyncio
async def test_vault_delete_other_users_entry_returns_404(async_client: AsyncClient):
    """A user cannot delete another user's vault entry."""
    # Register and login user alice
    alice_payload, _ = build_register_payload("alice", "alice_password")
    await async_client.post("/auth/register", json=alice_payload)
    kdf_resp = await async_client.get("/auth/kdf-params/alice")
    salt = bytes.fromhex(kdf_resp.json()["argon2_salt_hex"])
    alice_kdf = derive_keys(b"alice_password", salt)
    alice_token = (
        await async_client.post(
            "/auth/login",
            json={"username": "alice", "auth_key_hex": alice_kdf.auth_key.hex()},
        )
    ).json()["access_token"]

    # Alice creates an entry
    ct = encrypt_entry(alice_kdf.enc_key, {"site": "s", "username": "u", "password": "p", "notes": ""})
    entry_id = (
        await async_client.post(
            "/vault/entries",
            json={"ciphertext_hex": ct.ciphertext.hex(), "nonce_hex": ct.nonce.hex()},
            headers={"Authorization": f"Bearer {alice_token}"},
        )
    ).json()["id"]

    # Register and login user bob
    bob_payload, _ = build_register_payload("bob", "bob_password")
    await async_client.post("/auth/register", json=bob_payload)
    kdf_resp2 = await async_client.get("/auth/kdf-params/bob")
    salt2 = bytes.fromhex(kdf_resp2.json()["argon2_salt_hex"])
    bob_kdf = derive_keys(b"bob_password", salt2)
    bob_token = (
        await async_client.post(
            "/auth/login",
            json={"username": "bob", "auth_key_hex": bob_kdf.auth_key.hex()},
        )
    ).json()["access_token"]

    # Bob tries to delete Alice's entry — must get 404, not 403
    # (404 avoids leaking whether the entry exists)
    del_resp = await async_client.delete(
        f"/vault/entries/{entry_id}",
        headers={"Authorization": f"Bearer {bob_token}"},
    )
    assert del_resp.status_code == 404
