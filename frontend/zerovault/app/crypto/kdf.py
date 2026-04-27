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
    enc_key: bytes
    auth_key: bytes
    salt: bytes


def generate_salt() -> bytes:
    return os.urandom(SALT_LENGTH)


def derive_keys(master_password: bytes, salt: bytes) -> KDFResult:
    if len(salt) < SALT_LENGTH:
        raise ValueError(f"Salt must be at least {SALT_LENGTH} bytes, got {len(salt)}.")
    if not master_password:
        raise ValueError("master_password must not be empty.")

    master_key_material: bytes = hash_secret_raw(
        secret=master_password,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Type.ID,
    )

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
