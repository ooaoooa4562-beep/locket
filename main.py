# main.py - точка входа (FastAPI + aiogram webhook)
# Render держит как Web Service, Telegram шлёт webhook, UptimeRobot пингует /health.

import asyncio
import logging
import os
from contextlib import asynccontextmanager

from aiogram import Bot, Dispatcher
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.types import Update
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

import db
from handlers import register_handlers

# Логирование
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)
logger = logging.getLogger("locket")

# Конфигурация
BOT_TOKEN = os.getenv("BOT_TOKEN")
WEBHOOK_URL = os.getenv("WEBHOOK_URL")

if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN is not set")
if not WEBHOOK_URL:
    raise RuntimeError("WEBHOOK_URL is not set")

WEBHOOK_PATH = "/webhook"
WEBHOOK_FULL_URL = WEBHOOK_URL.rstrip("/") + WEBHOOK_PATH
WEBHOOK_SECRET = os.getenv("WEBHOOK_SECRET", "").strip() or None

# Bot и Dispatcher
bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)
dp = Dispatcher()

register_handlers(dp)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    await db.init_db()
    logger.info("Database initialized")

    await bot.delete_webhook(drop_pending_updates=True)
    await bot.set_webhook(
        url=WEBHOOK_FULL_URL,
        secret_token=WEBHOOK_SECRET,
        drop_pending_updates=True,
    )
    logger.info("Webhook set to %s", WEBHOOK_FULL_URL)

    yield

    logger.info("Shutting down...")
    await bot.delete_webhook(drop_pending_updates=False)
    await bot.session.close()


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@app.post(WEBHOOK_PATH)
async def telegram_webhook(request: Request) -> Response:
    if WEBHOOK_SECRET:
        header_secret = request.headers.get("X-Telegram-Bot-Api-Secret-Token")
        if header_secret != WEBHOOK_SECRET:
            logger.warning("Webhook: invalid secret token")
            return Response(status_code=403)

    try:
        data = await request.json()
    except Exception:
        logger.warning("Webhook: invalid JSON")
        return Response(status_code=400)

    update = Update.model_validate(data, context={"bot": bot})
    await dp.feed_update(bot, update)
    return Response(status_code=200)


@app.get("/")
async def root() -> JSONResponse:
    return JSONResponse({"service": "locket", "status": "running"})
