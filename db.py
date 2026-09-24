db.py — работа с базой данных SQLite.
Асинхронно через aiosqlite. Без ORM — чистый SQL, чтобы было понятно.
"""

import aiosqlite
import os
from pathlib import Path
from datetime import datetime, timezone

# Путь к БД берём из .env, по умолчанию — ./data/vault.db
DB_PATH = os.getenv("DATABASE_PATH", "./data/vault.db")

# Создаём папку data, если её нет
Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)


# === Инициализация схемы ===

async def init_db() -> None:
    """
    Создаёт таблицы, если их нет.
    Вызывается один раз при старте бота.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
        -- Пользователи
        CREATE TABLE IF NOT EXISTS users (
            user_id         INTEGER PRIMARY KEY,
            username        TEXT,
            password_hash   TEXT,
            password_salt   TEXT,
            totp_secret_enc TEXT,
            totp_secret_iv  TEXT,
            totp_enabled    INTEGER DEFAULT 0,
            created_at      TEXT NOT NULL,
            last_login_at   TEXT
        );

        -- Сохранённые элементы Vault
        CREATE TABLE IF NOT EXISTS items (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            content_type TEXT NOT NULL,
            content_enc  TEXT NOT NULL,
            content_iv   TEXT NOT NULL,
            preview      TEXT,
            created_at   TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        );

        CREATE INDEX IF NOT EXISTS idx_items_user_created
            ON items(user_id, created_at DESC);

        -- Попытки авторизации (для rate limiting)
        CREATE TABLE IF NOT EXISTS attempts (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER NOT NULL,
            attempt_type TEXT NOT NULL,
            success      INTEGER NOT NULL,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_attempts_user_time
            ON attempts(user_id, created_at DESC);
        """)
        await db.commit()


# === Пользователи ===

async def get_user(user_id: int) -> dict | None:
    """Возвращает пользователя или None."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM users WHERE user_id = ?", (user_id,)
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


async def create_user(user_id: int, username: str | None) -> None:
    """Регистрирует нового пользователя."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT OR IGNORE INTO users (user_id, username, created_at) "
            "VALUES (?, ?, ?)",
            (user_id, username, now),
        )
        await db.commit()


async def set_password(user_id: int, password_hash: str, salt: str) -> None:
    """Сохраняет хеш мастер-пароля и соль."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET password_hash = ?, password_salt = ? WHERE user_id = ?",
            (password_hash, salt, user_id),
        )
        await db.commit()


async def set_totp_secret(user_id: int, secret_enc: str, iv: str) -> None:
    """Сохраняет зашифрованный TOTP-секрет."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET totp_secret_enc = ?, totp_secret_iv = ?, totp_enabled = 1 "
            "WHERE user_id = ?",
            (secret_enc, iv, user_id),
        )
        await db.commit()


async def update_last_login(user_id: int) -> None:
    """Обновляет время последнего входа."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "UPDATE users SET last_login_at = ? WHERE user_id = ?",
            (now, user_id),
        )
        await db.commit()
# === Элементы Vault ===
[24.09.2026 19:50] Komick Op: async def save_item(
    user_id: int,
    content_type: str,
    content_enc: str,
    content_iv: str,
    preview: str | None = None,
) -> int:
    """Сохраняет зашифрованный элемент. Возвращает id."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        cur = await db.execute(
            "INSERT INTO items (user_id, content_type, content_enc, content_iv, preview, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, content_type, content_enc, content_iv, preview, now),
        )
        await db.commit()
        return cur.lastrowid


async def get_items(
    user_id: int,
    content_type: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    """Возвращает элементы пользователя, опционально по типу."""
    query = "SELECT id, content_type, preview, created_at FROM items WHERE user_id = ?"
    params: list = [user_id]
    if content_type:
        query += " AND content_type = ?"
        params.append(content_type)
    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(query, params) as cur:
            rows = await cur.fetchall()
            return [dict(r) for r in rows]


async def get_item(item_id: int, user_id: int) -> dict | None:
    """Возвращает один элемент (с зашифрованным содержимым) или None."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM items WHERE id = ? AND user_id = ?",
            (item_id, user_id),
        ) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None


# === Rate limiting ===

async def log_attempt(user_id: int, attempt_type: str, success: bool) -> None:
    """Логирует попытку авторизации (без значений пароля/кода!)."""
    now = datetime.now(timezone.utc).isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO attempts (user_id, attempt_type, success, created_at) "
            "VALUES (?, ?, ?, ?)",
            (user_id, attempt_type, 1 if success else 0, now),
        )
        await db.commit()


async def count_failed_attempts(user_id: int, attempt_type: str, since_iso: str) -> int:
    """Считает неудачные попытки с указанного времени."""
    async with aiosqlite.connect(DB_PATH) as db:
        async with db.execute(
            "SELECT COUNT(*) FROM attempts "
            "WHERE user_id = ? AND attempt_type = ? AND success = 0 AND created_at >= ?",
            (user_id, attempt_type, since_iso),
        ) as cur:
            row = await cur.fetchone()
            return row[0] if row else 0
