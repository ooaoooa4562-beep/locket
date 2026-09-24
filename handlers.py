"""
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
    waiting_new_password = State()
    waiting_confirm_password = State()
    waiting_totp_setup = State()
    waiting_password = State()
    waiting_totp = State()
    waiting_search = State()


# === In-memory сессии разблокировки ===
# user_id -> {expires_at, data_key}
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

async def check_lockout(user_id: int, attempt_type: str) -> tuple[bool, str]:
    """Асинхронная проверка блокировки."""
    now = datetime.now(timezone.utc)

    since_short = (now - timedelta(minutes=LOCKOUT_MINUTES)).isoformat()
    max_att = MAX_TOTP_ATTEMPTS if attempt_type == "totp" else MAX_PW_ATTEMPTS
    fails_short = await db.count_failed_attempts(user_id, attempt_type, since_short)
    if fails_short >= max_att:
        return True, f"⏳ Слишком много попыток. Подожди {LOCKOUT_MINUTES} мин."

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

    salt = crypto.generate_salt()
    pw_hash = crypto.hash_password(password, salt)
    await db.set_password(user_id, pw_hash, salt)

    totp_secret = crypto.generate_totp_secret()

    master_key = crypto.derive_key(password, salt)
    secret_enc, secret_iv = crypto.encrypt(master_key, totp_secret)
    await db.set_totp_secret(user_id, secret_enc, secret_iv)

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


# === /vault ===

async def cmd_vault(message: Message, state: FSMContext) -> None:
    """/vault — открыть хранилище."""
    await state.clear()
    user_id = message.from_user.id
    user = await db.get_user(user_id)

    if not user or not user.get("password_hash"):
        await message.answer("Сначала настрой Vault: /start")
        return

    if _is_unlocked(user_id):
        await message.answer(
            "🔓 <b>Vault разблокирован</b>",
            reply_markup=main_menu_kb(),
        )
        return

    await message.answer(
        "🔐 Vault заблокирован. Введи мастер-пароль:",
        reply_markup=locked_kb(),
    )


async def cb_unlock(callback: CallbackQuery, state: FSMContext) -> None:
    """Кнопка «Разблокировать»."""
    await callback.answer()
    await callback.message.answer("🔐 Введи мастер-пароль:")
    await state.set_state(Auth.waiting_password)


async def cb_menu(callback: CallbackQuery, state: FSMContext) -> None:
    """Возврат в главное меню."""
    await callback.answer()
    if not _is_unlocked(callback.from_user.id):
        await callback.message.edit_text(
            "🔒 Vault заблокирован.",
            reply_markup=locked_kb(),
        )
        return
    _touch(callback.from_user.id)
    await callback.message.edit_text(
        "🔓 <b>Vault разблокирован</b>",
        reply_markup=main_menu_kb(),
    )


# === Ввод пароля при входе ===

async def enter_password(message: Message, state: FSMContext) -> None:
    """Проверка мастер-пароля."""
    user_id = message.from_user.id
    password = message.text or ""

    try:
        await message.delete()
    except Exception:
        pass

    locked, lock_msg = await check_lockout(user_id, "password")
    if locked:
        await message.answer(lock_msg)
        await state.clear()
        return

    user = await db.get_user(user_id)
    if not user or not user.get("password_hash") or not user.get("password_salt"):
        await message.answer("Сначала настрой Vault: /start")
        await state.clear()
        return

    ok = crypto.verify_password(password, user["password_salt"], user["password_hash"])
    await db.log_attempt(user_id, "password", ok)

    if not ok:
        logger.warning("Failed password attempt for user %s", user_id)
        await message.answer("❌ Неверно. Попробуй ещё раз или /start.")
        return

    master_key = crypto.derive_key(password, user["password_salt"])

    if user.get("totp_enabled"):
        await state.update_data(temp_master_key=master_key.hex())
        await message.answer("🔑 Введи 6-значный код из приложения:")
        await state.set_state(Auth.waiting_totp)
    else:
        data_key = crypto.derive_data_key(master_key)
        _unlock(user_id, data_key)
        await db.update_last_login(user_id)
        await state.clear()
        await message.answer(
            "🔓 <b>Vault разблокирован</b>",
            reply_markup=main_menu_kb(),
        )


async def enter_totp(message: Message, state: FSMContext) -> None:
    """Проверка TOTP-кода."""
    user_id = message.from_user.id
    code = (message.text or "").strip()

    try:
        await message.delete()
    except Exception:
        pass

    locked, lock_msg = await check_lockout(user_id, "totp")
    if locked:
        await message.answer(lock_msg)
        await state.clear()
        return

    user = await db.get_user(user_id)
    data = await state.get_data()
    master_key_hex = data.get("temp_master_key")

    if not user or not master_key_hex:
        await message.answer("❌ Сессия истекла. Начни заново: /vault")
        await state.clear()
        return

    master_key = bytes.fromhex(master_key_hex)

    try:
        totp_secret = crypto.decrypt(
            master_key,
            user["totp_secret_enc"],
            user["totp_secret_iv"],
        )
    except Exception:
        logger.error("Failed to decrypt TOTP secret for user %s", user_id)
        await message.answer("❌ Ошибка. Попробуй заново: /vault")
        await state.clear()
        return

    ok = crypto.verify_totp(totp_secret, code)
    await db.log_attempt(user_id, "totp", ok)

    if not ok:
        logger.warning("Failed TOTP attempt for user %s", user_id)
        await message.answer("❌ Неверный код. Попробуй ещё раз.")
        return

    data_key = crypto.derive_data_key(master_key)
    _unlock(user_id, data_key)
    await db.update_last_login(user_id)
    await state.clear()
    await message.answer(
        "🔓 <b>Vault разблокирован</b>",
        reply_markup=main_menu_kb(),
    )


# === /lock ===

async def cmd_lock(message: Message, state: FSMContext) -> None:
    await state.clear()
    _lock(message.from_user.id)
    await message.answer("🔒 Vault заблокирован.")


async def cb_lock(callback: CallbackQuery, state: FSMContext) -> None:
    await callback.answer()
    _lock(callback.from_user.id)
    await callback.message.edit_text(
        "🔒 Vault заблокирован.",
        reply_markup=locked_kb(),
    )


# === Сохранение контента ===

def _detect_type(message: Message) -> str | None:
    """Определяет тип контента."""
    if message.photo:
        return "photo"
    if message.video:
        return "video"
    if message.document:
        return "document"
    if message.audio or message.voice:
        return "audio"
    if message.text:
        txt = message.text.strip()
        if txt.startswith("http://") or txt.startswith("https://") or txt.startswith("t.me/"):
            return "link"
        return "text"
    if message.forward_from or message.forward_from_chat:
        return "text"
    return None


async def save_content(message: Message, state: FSMContext) -> None:
    """Сохраняет любой контент. Требует разблокированного Vault."""
    user_id = message.from_user.id

    if message.text and message.text.startswith("/"):
        return

    user = await db.get_user(user_id)
    if not user or not user.get("password_hash"):
        await message.answer("Сначала настрой Vault: /start")
        return

    if not _is_unlocked(user_id):
        await message.answer(
            "🔒 Vault заблокирован. Разблокируй и пришли контент заново: /vault"
        )
        return

    _touch(user_id)

    content_type = _detect_type(message)
    if not content_type:
        await message.answer("🤷 Не понял, что это. Поддерживаются: текст, фото, видео, документы, аудио, ссылки.")
        return

    if content_type in ("text", "link"):
        raw = message.text or ""
        preview = raw[:80]
    elif content_type == "photo":
        file_id = message.photo[-1].file_id
        raw = f"file_id:{file_id}"
        preview = (message.caption[:80] if message.caption else "📸 Фото")
    elif content_type == "video":
        file_id = message.video.file_id
        raw = f"file_id:{file_id}"
        preview = (message.caption[:80] if message.caption else "🎥 Видео")
    elif content_type == "document":
        file_id = message.document.file_id
        name = message.document.file_name or "document"
        raw = f"file_id:{file_id}"
        preview = f"📄 {name}"[:80]
    elif content_type == "audio":
        f = message.audio or message.voice
        raw = f"file_id:{f.file_id}"
        preview = "🎵 Аудио"
    else:
        raw = ""
        preview = ""

    data_key = _sessions[user_id]["data_key"]
    content_enc, content_iv = crypto.encrypt(data_key, raw)

    await db.save_item(
        user_id=user_id,
        content_type=content_type,
        content_enc=content_enc,
        content_iv=content_iv,
        preview=preview,
    )

    emoji = {
        "text": "💬", "link": "🔗", "photo": "📸",
        "video": "🎥", "document": "📄", "audio": "🎵",
    }.get(content_type, "✅")

    await message.answer(f"{emoji} Сохранено. Открыть: /vault")


# === Просмотр и категории ===

async def cb_category(callback: CallbackQuery, state: FSMContext) -> None:
    """Показывает элементы по категории."""
    user_id = callback.from_user.id
    if not _is_unlocked(user_id):
        await callback.answer("🔒 Vault заблокирован", show_alert=True)
        return

    _touch(user_id)
    cat = callback.data.split(":", 1)[1]
    content_type = None if cat == "all" else cat

    items = await db.get_items(user_id, content_type=content_type, limit=20)

    if not items:
        text = "📭 Пусто."
    else:
        lines = ["<b>📂 Мои данные</b>\n"]
        for it in items:
            dt = it["created_at"][:16].replace("T", " ")
            emoji = {
                "text": "💬", "link": "🔗", "photo": "📸",
                "video": "🎥", "document": "📄", "audio": "🎵",
            }.get(it["content_type"], "•")
            preview = (it["preview"] or "")[:60]
            lines.append(f"{emoji} <code>#{it['id']}</code> {dt}\n{preview}")
        text = "\n\n".join(lines)

    await callback.answer()
    await callback.message.edit_text(
        text,
        reply_markup=categories_kb(),
    )


# === Поиск ===

async def cb_search(callback: CallbackQuery, state: FSMContext) -> None:
    """Кнопка «Поиск» — просит запрос."""
    user_id = callback.from_user.id
    if not _is_unlocked(user_id):
        await callback.answer("🔒 Vault заблокирован", show_alert=True)
        return
    _touch(user_id)
    await callback.answer()
    await callback.message.answer("🔎 Введи запрос для поиска по превью:")
    await state.set_state(Auth.waiting_search)


async def do_search(message: Message, state: FSMContext) -> None:
    """Поиск по превью."""
    user_id = message.from_user.id
    if not _is_unlocked(user_id):
        await message.answer("🔒 Vault заблокирован. /vault")
        await state.clear()
        return

    query = (message.text or "").strip().lower()
    if not query:
        await message.answer("Пустой запрос.")
        return

    items = await db.get_items(user_id, content_type=None, limit=200)
    found = [it for it in items if query in (it["preview"] or "").lower()]

    if not found:
        await message.answer("📭 Ничего не найдено.")
    else:
        lines = ["<b>🔎 Результаты:</b>\n"]
        for it in found[:20]:
            dt = it["created_at"][:16].replace("T", " ")
            preview = (it["preview"] or "")[:60]
            lines.append(f"<code>#{it['id']}</code> {dt}\n{preview}")
        await message.answer("\n\n".join(lines))

    await state.clear()


# === Настройки ===

async def cb_settings(callback: CallbackQuery) -> None:
    await callback.answer()
    await callback.message.edit_text(
        "⚙️ <b>Настройки</b>\n\n"
        f"⏱ Время сессии: {SESSION_TTL} мин.\n"
        f"🔑 2FA: включена\n\n"
        "Смена пароля и другие настройки — в следующих версиях.",
        reply_markup=InlineKeyboardMarkup(inline_keyboard=[
            [InlineKeyboardButton(text="⬅️ Назад", callback_data="menu")],
        ]),
    )


# === Регистрация хендлеров ===

def register_handlers(dp: Dispatcher) -> None:
    """Регистрирует все хендлеры. Вызывается из main.py."""
    dp.message.register(cmd_start, Command("start"))
    dp.message.register(cmd_vault, Command("vault"))
    dp.message.register(cmd_lock, Command("lock"))

    dp.callback_query.register(cb_unlock, F.data == "unlock")
    dp.callback_query.register(cb_menu, F.data == "menu")
    dp.callback_query.register(cb_lock, F.data == "lock")
    dp.callback_query.register(cb_settings, F.data == "settings")
    dp.callback_query.register(cb_search, F.data == "search")
    dp.callback_query.register(cb_category, F.data.startswith("cat:"))

    dp.message.register(confirm_password, Auth.waiting_confirm_password)
    dp.message.register(set_new_password, Auth.waiting_new_password)
    dp.message.register(verify_totp_setup, Auth.waiting_totp_setup)
    dp.message.register(enter_totp, Auth.waiting_totp)
    dp.message.register(enter_password, Auth.waiting_password)
    dp.message.register(do_search, Auth.waiting_search)

    dp.message.register(save_content)
