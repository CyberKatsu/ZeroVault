"""
zerovault.state
===============
Reflex application state.

Architecture note: zero-knowledge on the frontend
---------------------------------------------------
In a Reflex application the "backend" of Reflex State runs on the server.
This creates a philosophical tension with zero-knowledge design: the State
class lives in a Python process that the user does not control.

ZeroVault's approach:
  - The master password is NEVER stored in State beyond the moment of
    key derivation.  It is held only in a local variable and discarded.
  - enc_key is stored in State for the duration of the logged-in session.
    This is equivalent to a browser's in-memory session storage in a
    traditional SPA: it is in memory on the Reflex backend process and is
    cleared on logout or session expiry.
  - enc_key is NEVER persisted to disk, database, or sent over the network.
  - auth_key is derived, transmitted once for login/registration, then
    discarded — it is not stored in State.

For a production deployment, the Reflex backend would run over HTTPS, and
the server would be trusted at the process-memory level.  This matches the
trust model of any server-rendered application.

For a fully client-side zero-knowledge implementation (where enc_key truly
never leaves the user's machine), a JavaScript frontend using the WebCrypto
API would be required.  The Reflex approach is documented in SECURITY.md
as a known architectural limitation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional

import httpx
import reflex as rx

from zerovault.app.crypto.kdf import derive_keys, generate_salt
from zerovault.app.crypto.vault_cipher import VaultCiphertext, encrypt_entry, decrypt_entry
from zerovault.app.crypto.constants import (
    ARGON2_TIME_COST,
    ARGON2_MEMORY_COST_KIB,
    ARGON2_PARALLELISM,
)

try:
    from zxcvbn import zxcvbn as _zxcvbn
    def password_strength(password: str) -> int:
        """Return zxcvbn score 0-4."""
        return _zxcvbn(password)["score"] if password else 0
except ImportError:
    def password_strength(password: str) -> int:
        """Fallback: length-based heuristic if zxcvbn unavailable."""
        n = len(password)
        if n == 0:
            return 0
        if n < 8:
            return 1
        if n < 12:
            return 2
        if n < 20:
            return 3
        return 4


BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:38170")

STRENGTH_LABELS = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
STRENGTH_COLORS = ["#ef4444", "#f97316", "#eab308", "#22c55e", "#10b981"]


@dataclass
class VaultEntryDisplay:
    """A decrypted vault entry ready for display."""
    id: int
    site: str
    username: str
    password: str
    notes: str
    created_at: str
    show_password: bool = False


class ZeroVaultState(rx.State):
    """
    Root application state.

    Sensitive fields
    ----------------
    _enc_key_hex : str
        Hex-encoded 32-byte encryption key, stored in server memory for the
        session.  Never transmitted.  Cleared on logout.
    """

    # ── Auth state ────────────────────────────────────────────────────────────
    is_logged_in: bool = False
    current_username: str = ""
    access_token: str = ""

    # Encryption key stored server-side in Reflex State memory (NOT in DB, NOT transmitted)
    _enc_key_hex: str = ""

    # ── UI state ──────────────────────────────────────────────────────────────
    page: str = "login"  # "login" | "register" | "vault"
    error_message: str = ""
    success_message: str = ""
    is_loading: bool = False

    # ── Form fields ───────────────────────────────────────────────────────────
    form_username: str = ""
    form_master_password: str = ""
    form_confirm_password: str = ""

    # Vault entry form
    new_site: str = ""
    new_username: str = ""
    new_password: str = ""
    new_notes: str = ""

    # ── Vault display ─────────────────────────────────────────────────────────
    vault_entries: list[dict] = []
    # Which entry IDs have their password revealed
    revealed_ids: list[int] = []

    # ── Password strength ─────────────────────────────────────────────────────
    password_strength_score: int = 0
    password_strength_label: str = ""
    password_strength_color: str = "#6b7280"

    # ── Properties ───────────────────────────────────────────────────────────

    @rx.var
    def on_login_page(self) -> bool:
        return self.page == "login"

    @rx.var
    def on_register_page(self) -> bool:
        return self.page == "register"

    @rx.var
    def on_vault_page(self) -> bool:
        return self.page == "vault"

    @rx.var
    def has_error(self) -> bool:
        return bool(self.error_message)

    @rx.var
    def has_success(self) -> bool:
        return bool(self.success_message)

    # ── Navigation ────────────────────────────────────────────────────────────

    def go_to_register(self):
        self.page = "register"
        self._clear_messages()
        self._clear_forms()

    def go_to_login(self):
        self.page = "login"
        self._clear_messages()
        self._clear_forms()

    def _clear_messages(self):
        self.error_message = ""
        self.success_message = ""

    def _clear_forms(self):
        self.form_username = ""
        self.form_master_password = ""
        self.form_confirm_password = ""
        self.new_site = ""
        self.new_username = ""
        self.new_password = ""
        self.new_notes = ""
        self.password_strength_score = 0
        self.password_strength_label = ""
        self.password_strength_color = "#6b7280"

    # ── Password strength indicator ───────────────────────────────────────────

    def update_new_password(self, value: str):
        self.new_password = value
        score = password_strength(value)
        self.password_strength_score = score
        self.password_strength_label = STRENGTH_LABELS[score] if value else ""
        self.password_strength_color = STRENGTH_COLORS[score] if value else "#6b7280"

    # ── Registration ─────────────────────────────────────────────────────────

    async def register(self):
        self._clear_messages()

        if not self.form_username or not self.form_master_password:
            self.error_message = "Username and master password are required."
            return

        if self.form_master_password != self.form_confirm_password:
            self.error_message = "Passwords do not match."
            return

        if len(self.form_master_password) < 12:
            self.error_message = "Master password must be at least 12 characters."
            return

        self.is_loading = True
        yield

        try:
            # Client-side key derivation — enc_key stays local
            salt = generate_salt()
            kdf_result = derive_keys(
                self.form_master_password.encode("utf-8"), salt
            )

            payload = {
                "username": self.form_username,
                "auth_key_hex": kdf_result.auth_key.hex(),
                "argon2_salt_hex": salt.hex(),
                "argon2_time_cost": ARGON2_TIME_COST,
                "argon2_memory_cost_kib": ARGON2_MEMORY_COST_KIB,
                "argon2_parallelism": ARGON2_PARALLELISM,
            }

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{BACKEND_URL}/auth/register", json=payload, timeout=30.0
                )

            if resp.status_code == 201:
                self.success_message = "Account created! Please log in."
                self._clear_forms()
                self.page = "login"
            elif resp.status_code == 409:
                self.error_message = "Username already taken."
            else:
                self.error_message = f"Registration failed: {resp.json().get('detail', 'Unknown error')}"

        except httpx.RequestError as exc:
            self.error_message = f"Network error: {exc}"
        finally:
            self.is_loading = False

    # ── Login ─────────────────────────────────────────────────────────────────

    async def login(self):
        self._clear_messages()

        if not self.form_username or not self.form_master_password:
            self.error_message = "Username and master password are required."
            return

        self.is_loading = True
        yield

        try:
            # Step 1: Fetch KDF params from server
            async with httpx.AsyncClient() as client:
                params_resp = await client.get(
                    f"{BACKEND_URL}/auth/kdf-params/{self.form_username}",
                    timeout=10.0,
                )

            if params_resp.status_code == 404:
                self.error_message = "Invalid credentials."
                return

            kdf_data = params_resp.json()
            salt = bytes.fromhex(kdf_data["argon2_salt_hex"])

            # Step 2: Derive keys locally using server-stored params
            kdf_result = derive_keys(
                self.form_master_password.encode("utf-8"), salt
            )

            # Step 3: Send auth_key to server for verification
            async with httpx.AsyncClient() as client:
                login_resp = await client.post(
                    f"{BACKEND_URL}/auth/login",
                    json={
                        "username": self.form_username,
                        "auth_key_hex": kdf_result.auth_key.hex(),
                    },
                    timeout=30.0,
                )

            if login_resp.status_code == 200:
                data = login_resp.json()
                self.access_token = data["access_token"]
                self.current_username = self.form_username
                # Store enc_key in State memory — never transmitted
                self._enc_key_hex = kdf_result.enc_key.hex()
                self.is_logged_in = True
                self.page = "vault"
                self._clear_forms()
                yield ZeroVaultState.load_vault_entries
            else:
                self.error_message = "Invalid credentials."

        except httpx.RequestError as exc:
            self.error_message = f"Network error: {exc}"
        finally:
            self.is_loading = False

    # ── Logout ────────────────────────────────────────────────────────────────

    def logout(self):
        """Clear all sensitive state on logout."""
        self._enc_key_hex = ""
        self.access_token = ""
        self.current_username = ""
        self.is_logged_in = False
        self.vault_entries = []
        self.revealed_ids = []
        self.page = "login"
        self._clear_messages()
        self._clear_forms()

    # ── Vault operations ──────────────────────────────────────────────────────

    async def load_vault_entries(self):
        """Fetch encrypted entries from the server and decrypt locally."""
        if not self.access_token or not self._enc_key_hex:
            return

        enc_key = bytes.fromhex(self._enc_key_hex)

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"{BACKEND_URL}/vault/entries",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    timeout=10.0,
                )

            if resp.status_code != 200:
                self.error_message = "Failed to load vault."
                return

            entries = []
            for raw in resp.json():
                ct = VaultCiphertext(
                    ciphertext=bytes.fromhex(raw["ciphertext_hex"]),
                    nonce=bytes.fromhex(raw["nonce_hex"]),
                )
                try:
                    plaintext = decrypt_entry(enc_key, ct)
                    entries.append({
                        "id": raw["id"],
                        "site": plaintext.get("site", ""),
                        "username": plaintext.get("username", ""),
                        "password": plaintext.get("password", ""),
                        "notes": plaintext.get("notes", ""),
                        "created_at": raw["created_at"],
                    })
                except Exception:
                    # Tag verification failed — skip corrupted/tampered entry
                    entries.append({
                        "id": raw["id"],
                        "site": "[Decryption failed]",
                        "username": "",
                        "password": "",
                        "notes": "",
                        "created_at": raw["created_at"],
                    })

            self.vault_entries = entries

        except httpx.RequestError as exc:
            self.error_message = f"Network error: {exc}"

    async def add_vault_entry(self):
        """Encrypt a new vault entry locally and upload to server."""
        self._clear_messages()

        if not self.new_site or not self.new_password:
            self.error_message = "Site and password are required."
            return

        if not self._enc_key_hex:
            self.error_message = "Session error: encryption key unavailable."
            return

        self.is_loading = True
        yield

        enc_key = bytes.fromhex(self._enc_key_hex)
        plaintext = {
            "site": self.new_site,
            "username": self.new_username,
            "password": self.new_password,
            "notes": self.new_notes,
        }

        try:
            ct = encrypt_entry(enc_key, plaintext)

            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{BACKEND_URL}/vault/entries",
                    json={
                        "ciphertext_hex": ct.ciphertext.hex(),
                        "nonce_hex": ct.nonce.hex(),
                    },
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    timeout=10.0,
                )

            if resp.status_code == 201:
                self.new_site = ""
                self.new_username = ""
                self.new_password = ""
                self.new_notes = ""
                self.password_strength_score = 0
                self.password_strength_label = ""
                self.success_message = "Entry added."
                yield ZeroVaultState.load_vault_entries
            else:
                self.error_message = "Failed to save entry."

        except httpx.RequestError as exc:
            self.error_message = f"Network error: {exc}"
        finally:
            self.is_loading = False

    async def delete_vault_entry(self, entry_id: int):
        """Delete a vault entry by ID."""
        self._clear_messages()
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.delete(
                    f"{BACKEND_URL}/vault/entries/{entry_id}",
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    timeout=10.0,
                )
            if resp.status_code == 200:
                yield ZeroVaultState.load_vault_entries
            else:
                self.error_message = "Failed to delete entry."
        except httpx.RequestError as exc:
            self.error_message = f"Network error: {exc}"

    def toggle_reveal_password(self, entry_id: int):
        if entry_id in self.revealed_ids:
            self.revealed_ids = [i for i in self.revealed_ids if i != entry_id]
        else:
            self.revealed_ids = [*self.revealed_ids, entry_id]
