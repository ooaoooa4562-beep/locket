# db.py - работа с PostgreSQL (Neon).
# Асинхронно через asyncpg. Без ORM.

import os
import asyncpg
from datetime import datetime, timezone

# Connection string из Render Environment
DATABASE_URL = os.getenv("DATABASE_URL", "")

# Убираем channel_binding, если есть - иногда ломает asyncpg
if DATABASE_URL:
    DATABASE_URL = DATABASE_URL.replace("&channel_binding=require", "")
    DATABASE_URL = DATABASE_URL.replace("?channel_binding=require&", "?")
    DATABASE_URL = DATABASE_URL.replace("?channel_binding=require", "")

_pool: asyncpg.Pool | None = None


async def _get_pool() -> asyncpg.Pool:
    global _pool
    if _pool is None:
        if not DATABASE_URL:
            raise RuntimeError("DATABASE_URL is not set")
        _pool = await asyncpg.create_pool(
            DATABASE_URL,
            min_size=1,
            max_size=5,
            command_timeout=30,
        )
    return _pool


async def init_db() -> None:
    """Создаёт таблицы, если их нет."""
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id             BIGINT PRIMARY KEY,
            username            TEXT,
            password_hash       TEXT,
            password_salt       TEXT,
            recovery_code_hash  TEXT,
            recovery_code_salt  TEXT,
            code_issued_at      TEXT,
            created_at          TEXT NOT NULL,
            last_login_at       TEXT
        );

        CREATE TABLE IF NOT EXISTS items (
            id           SERIAL PRIMARY KEY,
            user_id      BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
            content_type TEXT NOT NULL,
            content_enc  TEXT NOT NULL,
            content_iv   TEXT NOT NULL,
            preview      TEXT,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_items_user_created
            ON items(user_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS attempts (
            id           SERIAL PRIMARY KEY,
            user_id      BIGINT NOT NULL,
            attempt_type TEXT NOT NULL,
            success      INTEGER NOT NULL,
            created_at   TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_attempts_user_time
            ON attempts(user_id, created_at DESC);
        """)


async def get_user(user_id: int) -> dict | None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM users WHERE user_id = $1", user_id
        )
        return dict(row) if row else None


async def create_user(user_id: int, username: str | None) -> None:
    now = datetime.now(timezone.utc).isoformat()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO users (user_id, username, created_at) "
            "VALUES ($1, $2, $3) ON CONFLICT (user_id) DO NOTHING",
            user_id, username, now,
        )


async def set_password(user_id: int, password_hash: str, salt: str) -> None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET password_hash = $1, password_salt = $2 WHERE user_id = $3",
            password_hash, salt, user_id,
        )


async def set_recovery_code(user_id: int, code_hash: str, salt: str) -> None:
    now = datetime.now(timezone.utc).isoformat()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET recovery_code_hash = $1, recovery_code_salt = $2, "
            "code_issued_at = $3 WHERE user_id = $4",
            code_hash, salt, now, user_id,
        )


async def update_last_login(user_id: int) -> None:
    now = datetime.now(timezone.utc).isoformat()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "UPDATE users SET last_login_at = $1 WHERE user_id = $2",
            now, user_id,
        )


async def save_item(
    user_id: int,
    content_type: str,
    content_enc: str,
    content_iv: str,
    preview: str | None = None,
) -> int:
    now = datetime.now(timezone.utc).isoformat()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "INSERT INTO items (user_id, content_type, content_enc, content_iv, preview, created_at) "
            "VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
            user_id, content_type, content_enc, content_iv, preview, now,
        )
        return row["id"]


async def get_items(
    user_id: int,
    content_type: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict]:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        if content_type:
            rows = await conn.fetch(
                "SELECT id, content_type, preview, created_at FROM items "
                "WHERE user_id = $1 AND content_type = $2 "
                "ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                user_id, content_type, limit, offset,
            )
        else:
            rows = await conn.fetch(
                "SELECT id, content_type, preview, created_at FROM items "
                "WHERE user_id = $1 "
                "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                user_id, limit, offset,
            )
        return [dict(r) for r in rows]


async def get_item(item_id: int, user_id: int) -> dict | None:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT * FROM items WHERE id = $1 AND user_id = $2",
            item_id, user_id,
        )
        return dict(row) if row else None


async def log_attempt(user_id: int, attempt_type: str, success: bool) -> None:
    now = datetime.now(timezone.utc).isoformat()
    pool = await _get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            "INSERT INTO attempts (user_id, attempt_type, success, created_at) "
            "VALUES ($1, $2, $3, $4)",
            user_id, attempt_type, 1 if success else 0, now,
        )


async def count_failed_attempts(user_id: int, attempt_type: str, since_iso: str) -> int:
    pool = await _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT COUNT(*) AS cnt FROM attempts "
            "WHERE user_id = $1 AND attempt_type = $2 AND success = 0 AND created_at >= $3",
            user_id, attempt_type, since_iso,
        )
        return row["cnt"] if row else 0
