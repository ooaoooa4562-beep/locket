# crypto.py - вся криптография проекта.
# Argon2id для пароля и кода, AES-256-GCM для шифрования.

import os
import base64
import secrets

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Параметры Argon2id
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

# Алфавит для recovery-кода (без 0, o, 1, i, l, 5, 8, b - похожих символов)
CODE_ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
CODE_LENGTH = 10


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


# === Recovery-код ===

def generate_recovery_code() -> str:
    """
    Генерирует 10-символьный код из алфавита без похожих символов.
    Возвращает в формате xxxx-xxxx-xx (для читаемости).
    """
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))
    return f"{raw[:4]}-{raw[4:8]}-{raw[8:]}"


def normalize_recovery_code(code: str) -> str:
    """
    Приводит код к нормальному виду: убирает дефисы/пробелы, нижний регистр.
    Используется при проверке, чтобы пользователь мог вводить по-разному.
    """
    return "".join(c for c in code.lower() if c.isalnum())


def hash_recovery_code(code: str, salt_hex: str) -> str:
    """
    Хеширует код через Argon2id. Возвращает hex.
    Перед хешированием нормализует (убирает дефисы, нижний регистр).
    """
    normalized = normalize_recovery_code(code)
    return derive_key(normalized, salt_hex).hex()


def verify_recovery_code(code: str, salt_hex: str, stored_hash: str) -> bool:
    """
    Проверяет recovery-код. Constant-time сравнение.
    """
    try:
        candidate = hash_recovery_code(code, salt_hex)
        return secrets.compare_digest(candidate, stored_hash)
    except Exception:
        return False
