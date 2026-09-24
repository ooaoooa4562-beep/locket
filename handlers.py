handlers.py — вся логика бота.

Что внутри:
- /start — регистрация, настройка пароля и 2FA.
- /vault — открытие хранилища (с авторизацией).
- /lock — мгновенная блокировка.
- Приём и сохранение контента.
- Просмотр, категории, поиск.
- Rate limiting и логирование попыток.

Безопасность:
- Пароль и код никогда не логируются.
- Сообщения с паролем и кодом удаляются сразу после обработки.
- Ошибки авторизации не раскрывают существование данных.
"""

import os
import logging
from datetime import datetime, timezone, timedelta

from aiogram import Dispatcher, F
from aiogram.filters import Command
from aiogram.types import (
    Message, CallbackQuery,
    InlineKeyboardMarkup, InlineKeyboardButton,
)
from aiogram.fsm.context import FSMContext
from aiogram.fsm.state import State, StatesGroup

import db
import crypto


logger = logging.getLogger("locket.handlers")


# === Настройки из окружения ===

SESSION_TTL = int(os.getenv("VAULT_SESSION_TTL", "15"))  # минут
MAX_PW_ATTEMPTS = int(os.getenv("MAX_PASSWORD_ATTEMPTS", "3"))
MAX_TOTP_ATTEMPTS = int(os.getenv("MAX_TOTP_ATTEMPTS", "3"))
LOCKOUT_MINUTES = int(os.getenv("LOCKOUT_MINUTES", "5"))
MAX_TOTAL_ATTEMPTS = int(os.getenv("MAX_TOTAL_ATTEMPTS", "10"))
LOCKOUT_LONG_HOURS = int(os.getenv("LOCKOUT_LONG_HOURS", "24"))


# === Состояния FSM ===

class Auth(StatesGroup):
    waiting_new_password = State()      # первый ввод пароля
    waiting_confirm_password = State()  # подтверждение пароля
    waiting_totp_setup = State()        # ввод кода при настройке 2FA
    waiting_password = State()          # ввод пароля при входе
    waiting_totp = State()              # ввод TOTP при входе
    waiting_search = State()            # ввод поискового запроса


# === In-memory сессии разблокировки ===
# user_id -> datetime до которого Vault разблокирован
# и data_key (ключ шифрования) в памяти
_sessions: dict[int, dict] = {}


def _is_unlocked(user_id: int) -> bool:
    """Проверяет, разблокирован ли Vault у пользователя."""
    s = _sessions.get(user_id)
    if not s:
        return False
    if datetime.now(timezone.utc) > s["expires_at"]:
        _lock(user_id)
        return False
    return True


def _unlock(user_id: int, data_key: bytes) -> None:
    """Разблокирует Vault на SESSION_TTL минут."""
    _sessions[user_id] = {
        "expires_at": datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL),
        "data_key": data_key,
    }


def _lock(user_id: int) -> None:
    """Стирает ключ из памяти и блокирует Vault."""
    if user_id in _sessions:
        # Затираем ключ (не гарантия, но снижает шанс утечки)
        s = _sessions.pop(user_id)
        try:
            s["data_key"] = b"\x00" * len(s["data_key"])
        except Exception:
            pass


def _touch(user_id: int) -> None:
    """Продлевает сессию при активности."""
    if user_id in _sessions:
        _sessions[user_id]["expires_at"] = (
            datetime.now(timezone.utc) + timedelta(minutes=SESSION_TTL)
        )


# === Клавиатуры ===

def main_menu_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="📂 Мои данные", callback_data="cat:all")],
        [InlineKeyboardButton(text="🔎 Поиск", callback_data="search")],
        [InlineKeyboardButton(text="⚙️ Настройки", callback_data="settings")],
        [InlineKeyboardButton(text="🔒 Заблокировать", callback_data="lock")],
    ])


def categories_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(text="📁 Все", callback_data="cat:all"),
            InlineKeyboardButton(text="📸 Фото", callback_data="cat:photo"),
        ],
        [
            InlineKeyboardButton(text="🎥 Видео", callback_data="cat:video"),
            InlineKeyboardButton(text="📄 Документы", callback_data="cat:document"),
        ],
        [
            InlineKeyboardButton(text="🔗 Ссылки", callback_data="cat:link"),
            InlineKeyboardButton(text="💬 Текст", callback_data="cat:text"),
        ],
        [InlineKeyboardButton(text="⬅️ Назад", callback_data="menu")],
    ])


def locked_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="🔐 Разблокировать", callback_data="unlock")],
    ])


# === Rate limiting ===

def _check_lockout(user_id: int, attempt_type: str) -> tuple[bool, str]:
    """
    Проверяет, не заблокирован ли пользователь.
    Возвращает (locked, сообщение).
    """
    now = datetime.now(timezone.utc)

    # Короткая блокировка
    since_short = (now - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    import asyncio
    # Синхронная обёртка — но у нас async контекст, используем отдельно ниже
    return False, ""


async def check_lockout(user_id: int, attempt_type: str) -> tuple[bool, str]:
    """Асинхронная проверка блокировки."""
    now = datetime.now(timezone.utc)

    # За последние LOCKOUT_MINUTES
    since_short = (now - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    max_att = MAX_TOTP_ATTEMPTS if attempt_type == "totp" else MAX_PW_ATTEMPTS
    fails_short = await db.count_failed_attempts(user_id, attempt_type, since_short)
    if fails_short >= max_att:
        return True, f"⏳ Слишком много попыток. Подожди {LOCKOUT_MINUTES} мин."

    # За последние LOCKOUT_LONG_HOURS
    since_long = (now - timedelta(hours=LOCKOUT_LONG_HOURS)).isoformat()
    fails_long = await db.count_failed_attempts(user_id, attempt_type, since_long)
    if fails_long >= MAX_TOTAL_ATTEMPTS:
        return True, f"⛔ Аккаунт временно заблокирован на {LOCKOUT_LONG_HOURS} ч."

    return False, ""


# === /start ===

async def cmd_start(message: Message, state: FSMContext) -> None:
    """/start — регистрация или приветствие."""
    await state.clear()
    user_id = message.from_user.id
    username = message.from_user.username

    user = await db.get_user(user_id)
    if not user:
        await db.create_user(user_id, username)
        logger.info("New user registered: %s", user_id)
        await message.answer(
            "🔐 <b>Locket</b> — твоё защищённое хранилище.\n\n"
            "Придумай <b>мастер-пароль</b>. Он будет использоваться для входа в Vault.\n"
            "⚠️ Запомни его — восстановить нельзя.\n\n"
            "Отправь пароль (минимум 8 символов)."
        )
        await state.set_state(Auth.waiting_new_password)
        return

    if user.get("password_hash"):
        await message.answer(
            "🔐 <b>Locket</b>\n\nVault создан. Для доступа — /vault.",
            reply_markup=locked_kb(),
        )
    else:
        await message.answer(
            "🔐 Придумай <b>мастер-пароль</b> (минимум 8 символов)."
        )
        await state.set_state(Auth.waiting_new_password)


# === Установка пароля ===

async def set_new_password(message: Message, state: FSMContext) -> None:
    """Первый ввод пароля."""
    password = message.text or ""
    # Удаляем сообщение с паролем
    try:
        await message.delete()
    except Exception:
        pass

    if len(password) < 8:
        await message.answer("❌ Пароль слишком короткий. Минимум 8 символов. Попробуй снова.")
        return

    await state.update_data(new_password=password)
    await message.answer("Повтори пароль для подтверждения.")
    await state.set_state(Auth.waiting_confirm_password)


async def confirm_password(message: Message, state: FSMContext) -> None:
    """Подтверждение пароля и настройка 2FA."""
    password = message.text or ""
    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    if password != data.get("new_password"):
        await message.answer("❌ Пароли не совпадают. Начни заново: /start")
        await state.clear()
        return

    user_id = message.from_user.id
 # Генерируем соль и хеш
    salt = crypto.generate_salt()
    pw_hash = crypto.hash_password(password, salt)
    await db.set_password(user_id, pw_hash, salt)

    # Генерируем TOTP-секрет
    totp_secret = crypto.generate_totp_secret()

    # Шифруем TOTP-секрет мастер-ключом
    master_key = crypto.derive_key(password, salt)
    secret_enc, secret_iv = crypto.encrypt(master_key, totp_secret)
    await db.set_totp_secret(user_id, secret_enc, secret_iv)

    # Показываем otpauth-ссылку
    uri = crypto.get_totp_uri(totp_secret, user_id)
    await message.answer(
        "✅ Пароль сохранён.\n\n"
        "🔑 <b>Настройка 2FA</b>\n\n"
        "Добавь этот секрет в Google Authenticator / Authy / 1Password:\n\n"
        f"<code>{totp_secret}</code>\n\n"
        "Или используй ссылку (скопируй и открой в приложении):\n"
        f"<code>{uri}</code>\n\n"
        "После добавления отправь <b>6-значный код</b> из приложения для подтверждения."
    )
    await state.update_data(temp_secret=totp_secret)
    await state.set_state(Auth.waiting_totp_setup)


async def verify_totp_setup(message: Message, state: FSMContext) -> None:
    """Проверка кода при настройке 2FA."""
    code = (message.text or "").strip()
    try:
        await message.delete()
    except Exception:
        pass

    data = await state.get_data()
    secret = data.get("temp_secret")
    if not secret:
        await message.answer("❌ Что-то пошло не так. Начни заново: /start")
        await state.clear()
        return

    if not crypto.verify_totp(secret, code):
        await message.answer("❌ Неверный код. Попробуй ещё раз.")
        return

    await state.clear()
    await db.update_last_login(message.from_user.id)
    logger.info("User %s completed setup", message.from_user.id)
    await message.answer(
        "🎉 <b>Vault готов!</b>\n\n"
        "Теперь можно отправлять мне сообщения, фото, видео, документы и ссылки — "
        "я сохраню их в защищённое хранилище.\n\n"
        "Для просмотра — /vault."
    )
