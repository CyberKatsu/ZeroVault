ARGON2_TIME_COST: int = 3
ARGON2_MEMORY_COST_KIB: int = 65536
ARGON2_PARALLELISM: int = 4
ARGON2_HASH_LENGTH: int = 64
ARGON2_TYPE: str = "id"

AES_KEY_LENGTH: int = 32
NONCE_LENGTH: int = 12
GCM_TAG_LENGTH: int = 16

SALT_LENGTH: int = 32

JWT_ALGORITHM: str = "HS256"

HKDF_INFO_ENC_KEY: bytes = b"zerovault-v1-encryption-key"
HKDF_INFO_AUTH_KEY: bytes = b"zerovault-v1-authentication-key"
