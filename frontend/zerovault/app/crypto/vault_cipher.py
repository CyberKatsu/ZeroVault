import json
import os
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from zerovault.app.crypto.constants import AES_KEY_LENGTH, GCM_TAG_LENGTH, NONCE_LENGTH


@dataclass(frozen=True)
class VaultCiphertext:
    ciphertext: bytes
    nonce: bytes

    def to_hex_dict(self) -> dict[str, str]:
        return {"ciphertext": self.ciphertext.hex(), "nonce": self.nonce.hex()}

    @classmethod
    def from_hex_dict(cls, data: dict[str, str]) -> "VaultCiphertext":
        return cls(
            ciphertext=bytes.fromhex(data["ciphertext"]),
            nonce=bytes.fromhex(data["nonce"]),
        )


def encrypt_entry(enc_key: bytes, plaintext_dict: dict[str, Any]) -> VaultCiphertext:
    if len(enc_key) != AES_KEY_LENGTH:
        raise ValueError(f"enc_key must be {AES_KEY_LENGTH} bytes, got {len(enc_key)}.")

    plaintext_bytes: bytes = json.dumps(plaintext_dict, sort_keys=True).encode("utf-8")
    nonce: bytes = os.urandom(NONCE_LENGTH)
    aesgcm = AESGCM(enc_key)
    ciphertext_with_tag: bytes = aesgcm.encrypt(nonce, plaintext_bytes, None)

    assert len(ciphertext_with_tag) == len(plaintext_bytes) + GCM_TAG_LENGTH

    return VaultCiphertext(ciphertext=ciphertext_with_tag, nonce=nonce)


def decrypt_entry(enc_key: bytes, vault_ciphertext: VaultCiphertext) -> dict[str, Any]:
    if len(enc_key) != AES_KEY_LENGTH:
        raise ValueError(f"enc_key must be {AES_KEY_LENGTH} bytes, got {len(enc_key)}.")
    if len(vault_ciphertext.nonce) != NONCE_LENGTH:
        raise ValueError(f"Nonce must be {NONCE_LENGTH} bytes, got {len(vault_ciphertext.nonce)}.")

    aesgcm = AESGCM(enc_key)
    plaintext_bytes: bytes = aesgcm.decrypt(vault_ciphertext.nonce, vault_ciphertext.ciphertext, None)

    return json.loads(plaintext_bytes.decode("utf-8"))
