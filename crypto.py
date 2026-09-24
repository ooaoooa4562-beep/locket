# crypto.py - вся криптография проекта.
# Argon2id для пароля и ключа, AES-256-GCM для шифрования, TOTP для 2FA.

import os
import base64
import secrets

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp

# Параметры Argon2id
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16


def generate_salt() -> str:
    return secrets.token_hex(ARGON2_SALT_LEN)


def derive_key(password: str, salt_hex: str) -> bytes:
    salt = bytes.fromhex(salt_hex)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def hash_password(password: str, salt_hex: str) -> str:
    return derive_key(password, salt_hex).hex()


def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    try:
        candidate = hash_password(password, salt_hex)
        return secrets.compare_digest(candidate, stored_hash)
    except Exception:
        return False


def _get_aesgcm(key: bytes) -> AESGCM:
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    return AESGCM(key)


def encrypt(key: bytes, plaintext: str) -> tuple[str, str]:
    iv = os.urandom(12)
    aes = _get_aesgcm(key)
    ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(ct).decode("ascii"), base64.b64encode(iv).decode("ascii")


def decrypt(key: bytes, ciphertext_b64: str, iv_b64: str) -> str:
    ct = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    aes = _get_aesgcm(key)
    pt = aes.decrypt(iv, ct, None)
    return pt.decode("utf-8")


def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, user_id: int, issuer: str = "Locket") -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=f"user_{user_id}",
        issuer_name=issuer,
    )


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=valid_window)
    except Exception:
        return False


def derive_data_key(master_key: bytes) -> bytes:
    return hash_secret_raw(
        secret=master_key,
        salt=b"locket-data-key-salt",
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
