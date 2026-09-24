crypto.py — вся криптография проекта.

Что внутри:
- Argon2id: хеширование мастер-пароля + деривация ключа шифрования.
- AES-256-GCM: шифрование/расшифровка данных и TOTP-секрета.
- TOTP: генерация секрета и проверка 6-значных кодов.

Правила:
- Пароль нигде не хранится в открытом виде.
- Ключ шифрования не хранится на сервере — он деривируется из пароля
  в момент ввода и живёт только в памяти.
- Ничего самодельного: только проверенные библиотеки.
"""

import os
import base64
import secrets

from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import pyotp


# === Параметры Argon2id ===
# time_cost=3, memory_cost=64MB, parallelism=4 — разумный баланс
# для серверной стороны. Если сервер слабый — можно уменьшить memory_cost.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 64 * 1024  # 64 MB
ARGON2_PARALLELISM = 4
ARGON2_HASH_LEN = 32  # 32 байта = 256 бит (ключ для AES-256)
ARGON2_SALT_LEN = 16


def generate_salt() -> str:
    """Генерирует случайную соль и возвращает в hex."""
    return secrets.token_hex(ARGON2_SALT_LEN)


def derive_key(password: str, salt_hex: str) -> bytes:
    """
    Деривирует 32-байтовый ключ из пароля и соли через Argon2id.
    Используется и для проверки пароля, и для шифрования данных.
    """
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
    """
    Возвращает hex-строку производного ключа (это и есть 'хеш' пароля).
    Мы храним именно его в БД — восстановить пароль из него нельзя.
    """
    return derive_key(password, salt_hex).hex()


def verify_password(password: str, salt_hex: str, stored_hash: str) -> bool:
    """
    Проверяет пароль, сравнивая производный ключ с сохранённым.
    Использует constant-time сравнение (secrets.compare_digest),
    чтобы избежать timing-атак.
    """
    try:
        candidate = hash_password(password, salt_hex)
        return secrets.compare_digest(candidate, stored_hash)
    except Exception:
        return False


# === AES-256-GCM ===

def _get_aesgcm(key: bytes) -> AESGCM:
    """Внутренняя обёртка. Проверяет длину ключа."""
    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    return AESGCM(key)


def encrypt(key: bytes, plaintext: str) -> tuple[str, str]:
    """
    Шифрует строку.
    Возвращает (ciphertext_b64, iv_b64).
    IV — 12 байт, случайный для каждой операции (требование GCM).
    """
    iv = os.urandom(12)
    aes = _get_aesgcm(key)
    ct = aes.encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(ct).decode("ascii"), base64.b64encode(iv).decode("ascii")


def decrypt(key: bytes, ciphertext_b64: str, iv_b64: str) -> str:
    """
    Расшифровывает строку.
    Бросает исключение, если данные повреждены или ключ неверный.
    """
    ct = base64.b64decode(ciphertext_b64)
    iv = base64.b64decode(iv_b64)
    aes = _get_aesgcm(key)
    pt = aes.decrypt(iv, ct, None)
    return pt.decode("utf-8")


# === TOTP ===

def generate_totp_secret() -> str:
    """Генерирует base32-секрет для TOTP (32 символа)."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, user_id: int, issuer: str = "Locket") -> str:
    """
    Возвращает otpauth://-ссылку для добавления в Google Authenticator / Authy.
    """
    return pyotp.TOTP(secret).provisioning_uri(
        name=f"user_{user_id}",
        issuer_name=issuer,
    )


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """
    Проверяет 6-значный код.
    valid_window=1 допускает ±30 секунд дрейфа часов.
    """
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=valid_window)
    except Exception:
        return False


# === Парольная фраза для генерации ключа шифрования данных ===
def derive_data_key(master_key: bytes) -> bytes:
    """
    Из ключа, производного от пароля, делает отдельный ключ
    для шифрования данных. Чтобы ключ от пароля и ключ для данных
    не совпадали — на всякий случай.
    """
    return hash_secret_raw(
        secret=master_key,
        salt=b"locket-data-key-salt",
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=32,
        type=Type.ID,
    )
