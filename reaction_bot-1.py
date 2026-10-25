"""
Reaction Platform - multi-tenant Telegram auto-reaction bot for Render.

Runtime: Python 3.11 (see .python-version)

Required environment variables:
  BOT_TOKEN       Master bot token from @BotFather
  DATABASE_URL    PostgreSQL connection string (Render Postgres "Internal Database URL")
  ENCRYPTION_KEY  Fernet key used to encrypt child-bot tokens at rest.
                  Generate one with:
                    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
Optional:
  PORT            HTTP port (Render injects this automatically)
  LOG_LEVEL       Logging level (default INFO)

Everything (web server, master bot, child bots, DB pool, background jobs)
runs on a single asyncio event loop.

Never commit secrets to source control.
"""
import asyncio
import html
import json
import logging
import os
import re
import secrets
import signal
import sys
import time
from datetime import datetime, timezone
from typing import Optional

import asyncpg
from aiohttp import web
from aiogram import Bot, Dispatcher, F, Router
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ChatMemberStatus, ChatType, ParseMode
from aiogram.exceptions import (
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNetworkError,
    TelegramRetryAfter,
    TelegramUnauthorizedError,
)
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    BotCommand,
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    Message,
    ReactionTypeEmoji,
    User,
)
from cryptography.fernet import Fernet, InvalidToken

# ================= PLATFORM CONFIGURATION =================
BOT_TOKEN = os.environ.get("BOT_TOKEN", "").strip()
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", "").strip()

ADMIN_ID = 8432635520                 # Numeric Telegram user ID of the platform owner
ADMIN_CHAT_ID = 8432635520            # Chat that receives admin notifications
ADMIN_IDS = {ADMIN_ID}                # Add more numeric user IDs if needed
FORCE_JOIN_CHANNEL_1 = "@nasimvaiz"
FORCE_JOIN_CHANNEL_2 = "@Animaxking77"
FORCE_JOIN_LINK_1 = "https://t.me/nasimvaiz"
FORCE_JOIN_LINK_2 = "https://t.me/Animaxking77"
SUPPORT_URL = FORCE_JOIN_LINK_1       # Where the Support button points
MAX_BOTS_PER_USER = 10                # Admins are exempt
# ================= END CONFIGURATION =====================

PORT = int(os.environ.get("PORT", "10000"))
START_TIME = time.time()
DEFAULT_EMOJIS = ["👍", "❤", "🔥"]
COOLDOWN_STEPS = [1, 2, 5, 10, 30]

MASTER_STATE = "Starting"
WEB_STATE = "Starting"
LAST_HEALTH_CHECK: Optional[str] = None
SHUTTING_DOWN = False
DB: Optional[asyncpg.Pool] = None
MASTER_USERNAME: Optional[str] = None
RUNTIME_LOCK = asyncio.Lock()
CHILD_RUNTIMES: dict = {}  # bot_id -> {"task": asyncio.Task, "ready": asyncio.Event}
WEB_RUNNER: Optional[web.AppRunner] = None
_FERNET: Optional[Fernet] = None

# In-memory conversational state (cleared on restart, which is acceptable).
PENDING_INPUT: dict = {}        # user_id -> (kind, payload)
PENDING_BROADCASTS: dict = {}   # token -> (admin_id, text)

logging.basicConfig(
    level=os.environ.get("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("reaction-platform")


# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
def esc(value) -> str:
    """HTML-escape any value for safe use with ParseMode.HTML."""
    return html.escape("" if value is None else str(value), quote=False)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_error(exc: BaseException) -> str:
    """Short, redacted error category. Never include raw exception text (may hold secrets)."""
    if isinstance(exc, TelegramUnauthorizedError):
        return "Invalid or revoked bot token"
    if isinstance(exc, TelegramForbiddenError):
        return "Telegram permission denied"
    if isinstance(exc, TelegramRetryAfter):
        return "Telegram rate limit reached"
    if isinstance(exc, TelegramBadRequest):
        return "Telegram rejected the request"
    if isinstance(exc, TelegramNetworkError):
        return "Telegram network error"
    if isinstance(exc, asyncpg.PostgresError):
        return "Database operation failed"
    if isinstance(exc, InvalidToken):
        return "Credential decryption failed"
    return type(exc).__name__


def normalize_emoji(value: str) -> str:
    # The Bot API lists reaction emoji without the U+FE0F variation selector.
    return value.replace("\ufe0f", "").strip()


def validate_config() -> None:
    errors = []
    if not BOT_TOKEN:
        errors.append("BOT_TOKEN is missing. Set it in Render > Environment.")
    if not DATABASE_URL:
        errors.append("DATABASE_URL is missing. Link a Render PostgreSQL database.")
    if not ENCRYPTION_KEY:
        errors.append(
            "ENCRYPTION_KEY is missing. Generate one with: "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    for name, value in (
        ("FORCE_JOIN_CHANNEL_1", FORCE_JOIN_CHANNEL_1),
        ("FORCE_JOIN_CHANNEL_2", FORCE_JOIN_CHANNEL_2),
    ):
        if not value or value.startswith("@YOUR_"):
            errors.append(f"{name} is still a placeholder; edit it at the top of reaction_bot.py.")
    if ADMIN_ID <= 0 or ADMIN_CHAT_ID == 0:
        errors.append("Set ADMIN_ID and ADMIN_CHAT_ID to valid Telegram IDs.")
    if errors:
        raise RuntimeError("Configuration error:\n- " + "\n- ".join(errors))


def init_crypto() -> None:
    global _FERNET
    try:
        _FERNET = Fernet(ENCRYPTION_KEY.encode())
    except Exception:
        raise RuntimeError(
            "ENCRYPTION_KEY is not a valid Fernet key (must be 32 url-safe base64-encoded bytes)."
        ) from None


def encrypt_token(token: str) -> str:
    return _FERNET.encrypt(token.encode()).decode()


def decrypt_token(value: str) -> str:
    return _FERNET.decrypt(value.encode()).decode()


# ----------------------------------------------------------------------------
# Database
# ----------------------------------------------------------------------------
SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  user_id BIGINT PRIMARY KEY,
  username TEXT,
  display_name TEXT NOT NULL,
  registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  blocked BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS child_bots (
  bot_id BIGINT PRIMARY KEY,
  owner_id BIGINT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
  username TEXT NOT NULL,
  name TEXT NOT NULL,
  token_enc TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  status TEXT NOT NULL DEFAULT 'Stopped',
  autostart BOOLEAN NOT NULL DEFAULT TRUE,
  last_error TEXT,
  last_activity TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS child_bots_owner_idx ON child_bots(owner_id);
CREATE UNIQUE INDEX IF NOT EXISTS child_bots_username_idx ON child_bots (LOWER(username));

CREATE TABLE IF NOT EXISTS connected_chats (
  bot_id BIGINT NOT NULL REFERENCES child_bots(bot_id) ON DELETE CASCADE,
  chat_id BIGINT NOT NULL,
  title TEXT NOT NULL,
  chat_type TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT TRUE,
  emoji_mode TEXT NOT NULL DEFAULT 'random',
  emojis JSONB NOT NULL DEFAULT '["👍","❤","🔥"]'::jsonb,
  cooldown_seconds INTEGER NOT NULL DEFAULT 2,
  PRIMARY KEY (bot_id, chat_id)
);

CREATE TABLE IF NOT EXISTS reaction_logs (
  id BIGSERIAL PRIMARY KEY,
  bot_id BIGINT NOT NULL REFERENCES child_bots(bot_id) ON DELETE CASCADE,
  chat_id BIGINT NOT NULL,
  message_id BIGINT NOT NULL,
  success BOOLEAN NOT NULL,
  error_category TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS reaction_logs_bot_idx ON reaction_logs(bot_id, created_at DESC);

CREATE TABLE IF NOT EXISTS broadcasts (
  id BIGSERIAL PRIMARY KEY,
  admin_id BIGINT NOT NULL,
  message_text TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  success_count INTEGER NOT NULL DEFAULT 0,
  failure_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS broadcast_deliveries (
  id BIGSERIAL PRIMARY KEY,
  broadcast_id BIGINT NOT NULL REFERENCES broadcasts(id) ON DELETE CASCADE,
  user_id BIGINT NOT NULL,
  success BOOLEAN NOT NULL,
  error_category TEXT
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_id BIGINT,
  action TEXT NOT NULL,
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""


async def _init_connection(conn: asyncpg.Connection) -> None:
    # Transparent JSON <-> Python conversion for JSONB columns.
    await conn.set_type_codec("jsonb", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")
    await conn.set_type_codec("json", encoder=json.dumps, decoder=json.loads, schema="pg_catalog")


async def init_db() -> None:
    global DB
    last_exc: Optional[BaseException] = None
    for attempt in range(1, 6):
        try:
            DB = await asyncpg.create_pool(
                dsn=DATABASE_URL,
                min_size=1,
                max_size=10,
                command_timeout=30,
                init=_init_connection,
            )
            break
        except Exception as exc:
            last_exc = exc
            log.warning("Database connection attempt %s/5 failed (%s)", attempt, safe_error(exc))
            await asyncio.sleep(min(2 * attempt, 10))
    else:
        raise RuntimeError(
            f"Could not connect to the database ({safe_error(last_exc)}). Check DATABASE_URL."
        ) from None
    await DB.execute(SCHEMA)
    log.info("Database ready")


async def audit(actor_id, action: str, details: Optional[dict] = None) -> None:
    try:
        await DB.execute(
            "INSERT INTO audit_logs(actor_id, action, details) VALUES($1,$2,$3)",
            actor_id, action, details or {},
        )
    except Exception as exc:
        log.warning("Could not write audit event %s (%s)", action, safe_error(exc))


async def ensure_user(user: User) -> None:
    await DB.execute(
        """
        INSERT INTO users(user_id, username, display_name) VALUES($1,$2,$3)
        ON CONFLICT (user_id) DO UPDATE
          SET username=EXCLUDED.username, display_name=EXCLUDED.display_name
        """,
        user.id, user.username, (user.full_name or "Telegram user")[:256],
    )


async def get_owned_bot(user_id: int, bot_id: int):
    return await DB.fetchrow("SELECT * FROM child_bots WHERE bot_id=$1 AND owner_id=$2", bot_id, user_id)


async def get_bot_row(bot_id: int):
    return await DB.fetchrow("SELECT * FROM child_bots WHERE bot_id=$1", bot_id)


async def maintenance_loop() -> None:
    """Keep the reaction log table from growing forever."""
    while True:
        try:
            await DB.execute("DELETE FROM reaction_logs WHERE created_at < NOW() - INTERVAL '30 days'")
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("Log cleanup failed (%s)", safe_error(exc))
        await asyncio.sleep(3600)


# ----------------------------------------------------------------------------
# Telegram UI helpers
# ----------------------------------------------------------------------------
def is_admin(user_id: int) -> bool:
    return user_id in ADMIN_IDS


def main_menu(user_id: int) -> InlineKeyboardMarkup:
    rows = [
        [InlineKeyboardButton(text="🤖 Create Bot", callback_data="create"),
         InlineKeyboardButton(text="📂 My Bots", callback_data="mybots:0")],
        [InlineKeyboardButton(text="👤 My Profile", callback_data="profile"),
         InlineKeyboardButton(text="📊 My Statistics", callback_data="stats")],
        [InlineKeyboardButton(text="⚙️ Settings", callback_data="settings"),
         InlineKeyboardButton(text="📖 Help", callback_data="help")],
        [InlineKeyboardButton(text="🛟 Support", url=SUPPORT_URL)],
    ]
    if is_admin(user_id):
        rows.append([InlineKeyboardButton(text="🛡️ Admin Panel", callback_data="admin")])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def force_join_keyboard() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="Join Channel 1", url=FORCE_JOIN_LINK_1)],
        [InlineKeyboardButton(text="Join Channel 2", url=FORCE_JOIN_LINK_2)],
        [InlineKeyboardButton(text="✅ Check Membership", callback_data="check_join")],
    ])


def bot_keyboard(bot_id: int) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="▶️ Start", callback_data=f"botstart:{bot_id}"),
         InlineKeyboardButton(text="⏹ Stop", callback_data=f"botstop:{bot_id}")],
        [InlineKeyboardButton(text="🔄 Restart", callback_data=f"botrestart:{bot_id}"),
         InlineKeyboardButton(text="➕ Add Group/Channel", callback_data=f"botaddchat:{bot_id}")],
        [InlineKeyboardButton(text="⚙️ Reaction Settings", callback_data=f"botsettings:{bot_id}"),
         InlineKeyboardButton(text="📜 Activity Logs", callback_data=f"botlogs:{bot_id}")],
        [InlineKeyboardButton(text="🗑 Remove Bot", callback_data=f"botremove:{bot_id}"),
         InlineKeyboardButton(text="🏠 Home", callback_data="home")],
    ])


def chat_settings_view(bot_id: int, row):
    emojis = row["emojis"]
    if isinstance(emojis, str):
        emojis = json.loads(emojis)
    mode = "random" if row["emoji_mode"] == "random" else "fixed (first emoji)"
    text = (
        f"<b>{esc(row['title'])}</b>\n"
        f"Chat ID: <code>{row['chat_id']}</code>\n"
        f"Type: {esc(row['chat_type'])}\n"
        f"Reactions: {'ON' if row['enabled'] else 'OFF'}\n"
        f"Mode: {mode}\n"
        f"Cooldown: {row['cooldown_seconds']}s\n"
        f"Emojis: {' '.join(esc(e) for e in emojis)}"
    )

    def cb(action: str) -> str:
        return f"cs:{action}:{bot_id}:{row['chat_id']}"

    markup = InlineKeyboardMarkup(inline_keyboard=[
        [InlineKeyboardButton(text="⏯ On/Off", callback_data=cb("toggle")),
         InlineKeyboardButton(text="🔀 Mode", callback_data=cb("mode"))],
        [InlineKeyboardButton(text="⏱ Cooldown", callback_data=cb("cd")),
         InlineKeyboardButton(text="😀 Set Emojis", callback_data=cb("emoji"))],
        [InlineKeyboardButton(text="🗑 Disconnect Chat", callback_data=cb("remove"))],
    ])
    return text, markup


async def send(bot: Bot, call: CallbackQuery, text: str, reply_markup=None) -> None:
    """Reply to a callback in the user's private chat (safe even for old/inaccessible messages)."""
    await bot.send_message(call.from_user.id, text, reply_markup=reply_markup)


async def notify_admin(bot: Bot, text: str) -> None:
    try:
        await bot.send_message(ADMIN_CHAT_ID, text)
    except Exception as exc:
        log.warning("Admin notification failed (%s)", safe_error(exc))


async def membership_check(bot: Bot, user_id: int) -> list:
    missing = []
    for channel in (FORCE_JOIN_CHANNEL_1, FORCE_JOIN_CHANNEL_2):
        try:
            member = await bot.get_chat_member(channel, user_id)
            ok = member.status in (
                ChatMemberStatus.MEMBER,
                ChatMemberStatus.ADMINISTRATOR,
                ChatMemberStatus.CREATOR,
            ) or (member.status == ChatMemberStatus.RESTRICTED and getattr(member, "is_member", False))
            if not ok:
                missing.append(channel)
        except Exception as exc:
            log.warning("Membership verification unavailable for %s (%s)", channel, safe_error(exc))
            # Fail closed: an API failure must not grant access.
            missing.append(f"{channel} (verification unavailable)")
    return missing


async def require_join(event, bot: Bot) -> bool:
    user = event.from_user
    missing = await membership_check(bot, user.id)
    if not missing:
        return True
    text = (
        "আগে নিচের দুইটি চ্যানেলে যোগ দিন, তারপর Check Membership চাপুন.\n\n"
        "যে চ্যানেল যাচাই করা যায়নি/যেখানে যোগ দিতে হবে:\n"
        + "\n".join(f"• {esc(x)}" for x in missing)
    )
    if isinstance(event, CallbackQuery):
        await bot.send_message(user.id, text, reply_markup=force_join_keyboard())
        await event.answer("Membership not confirmed", show_alert=True)
    else:
        await event.answer(text, reply_markup=force_join_keyboard())
    return False


def parse_emojis(text: str) -> list:
    tokens = [normalize_emoji(t) for t in re.split(r"[\s,]+", text.strip()) if t]
    result = []
    for tok in tokens:
        if not tok or len(tok) > 6:
            continue
        if any(ch.isascii() and ch.isalnum() for ch in tok):
            continue
        if tok not in result:
            result.append(tok)
    return result[:10]


# ----------------------------------------------------------------------------
# Child bot runtime
# ----------------------------------------------------------------------------
def build_child_router(bot_id: int) -> Router:
    router = Router(name=f"child-reactions-{bot_id}")
    last_reaction: dict = {}  # chat_id -> monotonic timestamp (per-chat cooldown)

    async def react(message: Message, bot: Bot) -> None:
        if message.from_user and message.from_user.is_bot:
            return
        chat_id = message.chat.id
        row = await DB.fetchrow(
            "SELECT emoji_mode, emojis, cooldown_seconds FROM connected_chats "
            "WHERE bot_id=$1 AND chat_id=$2 AND enabled",
            bot_id, chat_id,
        )
        if not row:
            return
        now = time.monotonic()
        previous = last_reaction.get(chat_id)
        if previous is not None and now - previous < row["cooldown_seconds"]:
            return
        last_reaction[chat_id] = now

        emojis = row["emojis"]
        if isinstance(emojis, str):
            emojis = json.loads(emojis)
        emojis = [normalize_emoji(e) for e in (emojis or [])] or ["👍"]
        emoji = secrets.choice(emojis) if row["emoji_mode"] == "random" else emojis[0]

        success, category = True, None
        try:
            await bot.set_message_reaction(
                chat_id=chat_id,
                message_id=message.message_id,
                reaction=[ReactionTypeEmoji(emoji=emoji)],
                is_big=False,
            )
        except Exception as exc:
            success, category = False, safe_error(exc)
            if isinstance(exc, TelegramRetryAfter):
                await asyncio.sleep(min(float(exc.retry_after), 30))
        try:
            await DB.execute(
                "INSERT INTO reaction_logs(bot_id,chat_id,message_id,success,error_category) "
                "VALUES($1,$2,$3,$4,$5)",
                bot_id, chat_id, message.message_id, success, category,
            )
            await DB.execute("UPDATE child_bots SET last_activity=NOW() WHERE bot_id=$1", bot_id)
        except Exception as exc:
            log.warning("Could not record reaction for bot_id=%s (%s)", bot_id, safe_error(exc))

    # Groups/supergroups deliver `message`; channels deliver `channel_post`.
    router.message.register(react)
    router.channel_post.register(react)
    return router


async def run_child(bot_id: int, token: str, ready: asyncio.Event) -> None:
    bot = Bot(token=token, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    dp = Dispatcher()
    dp.include_router(build_child_router(bot_id))
    try:
        me = await bot.get_me()
        await DB.execute("UPDATE child_bots SET status='Running', last_error=NULL WHERE bot_id=$1", bot_id)
        ready.set()
        log.info("Child runtime started: bot_id=%s username=@%s", bot_id, me.username)
        await dp.start_polling(
            bot,
            allowed_updates=dp.resolve_used_update_types(),
            handle_signals=False,
        )
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        category = safe_error(exc)
        log.warning("Child runtime failed bot_id=%s category=%s", bot_id, category)
        try:
            await DB.execute("UPDATE child_bots SET status='Error', last_error=$2 WHERE bot_id=$1", bot_id, category)
        except Exception as exc:
            log.debug("Ignored non-fatal error (%s)", safe_error(exc))
    finally:
        ready.set()
        try:
            await bot.session.close()
        except Exception as exc:
            log.debug("Ignored non-fatal error (%s)", safe_error(exc))
        async with RUNTIME_LOCK:
            runtime = CHILD_RUNTIMES.get(bot_id)
            # Only remove our own entry; a restart may already have registered a newer task.
            if runtime and runtime["task"] is asyncio.current_task():
                CHILD_RUNTIMES.pop(bot_id, None)
        try:
            await DB.execute("UPDATE child_bots SET status='Stopped' WHERE bot_id=$1 AND status='Running'", bot_id)
        except Exception as exc:
            log.debug("Ignored non-fatal error (%s)", safe_error(exc))


async def start_child(bot_id: int, owner_id: Optional[int] = None, remember: bool = True) -> str:
    """Start a child bot. owner_id=None skips the ownership check (internal resume only)."""
    row = await get_bot_row(bot_id)
    if not row or (owner_id is not None and row["owner_id"] != owner_id):
        raise PermissionError("Bot not found or not owned by you.")
    try:
        token = decrypt_token(row["token_enc"])
    except Exception as exc:
        await DB.execute(
            "UPDATE child_bots SET status='Error', last_error=$2 WHERE bot_id=$1",
            bot_id, safe_error(exc),
        )
        return "Error"
    if remember:
        await DB.execute("UPDATE child_bots SET autostart=TRUE WHERE bot_id=$1", bot_id)
    async with RUNTIME_LOCK:
        existing = CHILD_RUNTIMES.get(bot_id)
        if existing and not existing["task"].done():
            return "Already running"
        ready = asyncio.Event()
        task = asyncio.create_task(run_child(bot_id, token, ready), name=f"child-bot-{bot_id}")
        CHILD_RUNTIMES[bot_id] = {"task": task, "ready": ready}
    try:
        await asyncio.wait_for(ready.wait(), timeout=10)
    except asyncio.TimeoutError:
        return "Starting"
    refreshed = await get_bot_row(bot_id)
    return refreshed["status"] if refreshed else "Stopped"


async def stop_child(bot_id: int, owner_id: int) -> str:
    row = await get_owned_bot(owner_id, bot_id)
    if not row:
        raise PermissionError("Bot not found or not owned by you.")
    # An explicit stop means: do not auto-start after the next deploy/restart.
    await DB.execute("UPDATE child_bots SET autostart=FALSE WHERE bot_id=$1", bot_id)
    async with RUNTIME_LOCK:
        runtime = CHILD_RUNTIMES.get(bot_id)
        task = runtime["task"] if runtime else None
    if task is None or task.done():
        await DB.execute("UPDATE child_bots SET status='Stopped' WHERE bot_id=$1", bot_id)
        return "Already stopped"
    task.cancel()
    await asyncio.wait({task}, timeout=10)
    await DB.execute("UPDATE child_bots SET status='Stopped' WHERE bot_id=$1", bot_id)
    return "Stopped"


async def resume_child_bots() -> None:
    rows = await DB.fetch("SELECT bot_id FROM child_bots WHERE autostart ORDER BY created_at")
    semaphore = asyncio.Semaphore(5)

    async def one(bot_id: int) -> None:
        async with semaphore:
            try:
                await start_child(bot_id, None, remember=False)
            except Exception as exc:
                log.warning("Could not resume child bot %s (%s)", bot_id, safe_error(exc))

    await asyncio.gather(*(one(r["bot_id"]) for r in rows))
    log.info("Resumed %s child bot(s)", len(rows))


# ----------------------------------------------------------------------------
# Master bot router
# ----------------------------------------------------------------------------
def build_master_router() -> Router:
    router = Router(name="master")

    # ---- Commands (registered BEFORE the generic text handler) ----
    @router.message(CommandStart())
    async def start(message: Message, bot: Bot):
        PENDING_INPUT.pop(message.from_user.id, None)
        await ensure_user(message.from_user)
        if not is_admin(message.from_user.id) and not await require_join(message, bot):
            return
        await message.answer(
            "Welcome to the Multi-Bot Auto Reaction Platform.",
            reply_markup=main_menu(message.from_user.id),
        )

    @router.message(Command("cancel"))
    async def cancel(message: Message):
        PENDING_INPUT.pop(message.from_user.id, None)
        await message.answer("Cancelled.")

    @router.message(Command("broadcast"))
    async def broadcast_start(message: Message):
        if not is_admin(message.from_user.id):
            return
        parts = (message.text or "").split(None, 1)
        text_content = parts[1].strip() if len(parts) > 1 else ""
        if not text_content:
            await message.answer("Usage: /broadcast Your message here")
            return
        key = secrets.token_urlsafe(12)
        PENDING_BROADCASTS[key] = (message.from_user.id, text_content)
        count = await DB.fetchval("SELECT COUNT(*) FROM users WHERE NOT blocked")
        await message.answer(
            f"Broadcast preview:\n\n{esc(text_content)}\n\nEligible users: {count}\nConfirm?",
            reply_markup=InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="✅ Confirm", callback_data=f"bcconfirm:{key}"),
                InlineKeyboardButton(text="Cancel", callback_data=f"bccancel:{key}"),
            ]]),
        )

    # ---- Navigation ----
    @router.callback_query(F.data == "check_join")
    async def check_join(call: CallbackQuery, bot: Bot):
        if not await require_join(call, bot):
            return
        await send(bot, call, "Membership verified. Welcome!", main_menu(call.from_user.id))
        await call.answer("Verified")

    @router.callback_query(F.data == "home")
    async def home(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id) and not await require_join(call, bot):
            return
        await send(bot, call, "Main menu:", main_menu(call.from_user.id))
        await call.answer()

    @router.callback_query(F.data == "create")
    async def create(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id) and not await require_join(call, bot):
            return
        await ensure_user(call.from_user)
        PENDING_INPUT[call.from_user.id] = ("create", None)
        await send(
            bot, call,
            "Send your BotFather token in this private chat. Only submit a token for a bot you own "
            "or are authorized to manage. The message will be deleted where Telegram permits.\n"
            "Send /cancel to abort.",
        )
        await call.answer()

    @router.callback_query(F.data == "mybots:0")
    async def mybots(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id) and not await require_join(call, bot):
            return
        rows = await DB.fetch(
            "SELECT bot_id,username,name,status FROM child_bots "
            "WHERE owner_id=$1 ORDER BY created_at DESC LIMIT 20",
            call.from_user.id,
        )
        if not rows:
            await send(bot, call, "You have no registered bots yet.")
        else:
            for r in rows:
                await send(
                    bot, call,
                    f"<b>{esc(r['name'])}</b> (@{esc(r['username'])})\n"
                    f"ID: <code>{r['bot_id']}</code>\nStatus: {esc(r['status'])}",
                    bot_keyboard(r["bot_id"]),
                )
        await call.answer()

    # ---- Child bot controls ----
    @router.callback_query(F.data.startswith("botstart:"))
    async def botstart(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        try:
            status = await start_child(bot_id, call.from_user.id)
        except PermissionError:
            await call.answer("Not authorized.", show_alert=True)
            return
        await send(bot, call, f"Runtime status: {esc(status)}", bot_keyboard(bot_id))
        await call.answer()

    @router.callback_query(F.data.startswith("botstop:"))
    async def botstop(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        try:
            status = await stop_child(bot_id, call.from_user.id)
        except PermissionError:
            await call.answer("Not authorized.", show_alert=True)
            return
        await send(bot, call, f"Runtime status: {esc(status)}", bot_keyboard(bot_id))
        await call.answer()

    @router.callback_query(F.data.startswith("botrestart:"))
    async def botrestart(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        try:
            await stop_child(bot_id, call.from_user.id)
            status = await start_child(bot_id, call.from_user.id)
        except PermissionError:
            await call.answer("Not authorized.", show_alert=True)
            return
        await send(bot, call, f"Runtime status: {esc(status)}", bot_keyboard(bot_id))
        await call.answer()

    @router.callback_query(F.data.startswith("botaddchat:"))
    async def botaddchat(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        if not await get_owned_bot(call.from_user.id, bot_id):
            await call.answer("Not authorized.", show_alert=True)
            return
        PENDING_INPUT[call.from_user.id] = ("addchat", bot_id)
        await send(
            bot, call,
            "Add the child bot to the intended group/channel (as admin for channels), then either "
            "forward any message from that chat here, or send its numeric chat ID or @username. "
            "The bot must already be a member.\nSend /cancel to abort.",
        )
        await call.answer()

    @router.callback_query(F.data.startswith("botsettings:"))
    async def botsettings(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        if not await get_owned_bot(call.from_user.id, bot_id):
            await call.answer("Not authorized.", show_alert=True)
            return
        rows = await DB.fetch(
            "SELECT * FROM connected_chats WHERE bot_id=$1 ORDER BY title LIMIT 20", bot_id
        )
        if not rows:
            await send(bot, call, "No chats connected yet. Use ➕ Add Group/Channel first.")
        for row in rows:
            text, markup = chat_settings_view(bot_id, row)
            await send(bot, call, text, markup)
        await call.answer()

    @router.callback_query(F.data.startswith("cs:"))
    async def chat_settings_action(call: CallbackQuery, bot: Bot):
        try:
            _, action, bot_id_s, chat_id_s = call.data.split(":", 3)
            bot_id, chat_id = int(bot_id_s), int(chat_id_s)
        except ValueError:
            await call.answer("Invalid request.", show_alert=True)
            return
        uid = call.from_user.id
        if not await get_owned_bot(uid, bot_id):
            await call.answer("Not authorized.", show_alert=True)
            return
        row = await DB.fetchrow(
            "SELECT * FROM connected_chats WHERE bot_id=$1 AND chat_id=$2", bot_id, chat_id
        )
        if not row:
            await call.answer("Chat not found.", show_alert=True)
            return

        if action == "toggle":
            await DB.execute(
                "UPDATE connected_chats SET enabled = NOT enabled WHERE bot_id=$1 AND chat_id=$2",
                bot_id, chat_id,
            )
        elif action == "mode":
            new_mode = "fixed" if row["emoji_mode"] == "random" else "random"
            await DB.execute(
                "UPDATE connected_chats SET emoji_mode=$3 WHERE bot_id=$1 AND chat_id=$2",
                bot_id, chat_id, new_mode,
            )
        elif action == "cd":
            current = row["cooldown_seconds"]
            larger = [s for s in COOLDOWN_STEPS if s > current]
            new_cd = larger[0] if larger else COOLDOWN_STEPS[0]
            await DB.execute(
                "UPDATE connected_chats SET cooldown_seconds=$3 WHERE bot_id=$1 AND chat_id=$2",
                bot_id, chat_id, new_cd,
            )
        elif action == "emoji":
            PENDING_INPUT[uid] = ("emojis", (bot_id, chat_id))
            await send(
                bot, call,
                "Send up to 10 reaction emoji separated by spaces, e.g. 👍 ❤ 🔥 🎉\n"
                "Only emoji Telegram allows as reactions will work. Send /cancel to abort.",
            )
            await call.answer()
            return
        elif action == "remove":
            await DB.execute(
                "DELETE FROM connected_chats WHERE bot_id=$1 AND chat_id=$2", bot_id, chat_id
            )
            try:
                await bot.edit_message_text(
                    "Chat disconnected.", chat_id=uid, message_id=call.message.message_id
                )
            except Exception as exc:
                log.debug("Ignored non-fatal error (%s)", safe_error(exc))
            await call.answer("Disconnected")
            return
        else:
            await call.answer("Unknown action.", show_alert=True)
            return

        row = await DB.fetchrow(
            "SELECT * FROM connected_chats WHERE bot_id=$1 AND chat_id=$2", bot_id, chat_id
        )
        if row and call.message:
            text, markup = chat_settings_view(bot_id, row)
            try:
                await bot.edit_message_text(
                    text, chat_id=uid, message_id=call.message.message_id, reply_markup=markup
                )
            except TelegramBadRequest as exc:
                log.debug("Ignored non-fatal error (%s)", safe_error(exc))
        await call.answer("Updated")

    @router.callback_query(F.data.startswith("botlogs:"))
    async def botlogs(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        if not await get_owned_bot(call.from_user.id, bot_id):
            await call.answer("Not authorized.", show_alert=True)
            return
        rows = await DB.fetch(
            "SELECT success,error_category,created_at FROM reaction_logs "
            "WHERE bot_id=$1 ORDER BY created_at DESC LIMIT 10",
            bot_id,
        )
        if rows:
            lines = [
                f"{r['created_at']:%Y-%m-%d %H:%M} UTC - {'OK' if r['success'] else esc(r['error_category'])}"
                for r in rows
            ]
            text = "Recent activity:\n" + "\n".join(lines)
        else:
            text = "Recent activity:\nNo reactions logged yet."
        await send(bot, call, text)
        await call.answer()

    @router.callback_query(F.data.startswith("botremove:"))
    async def botremove(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        if not await get_owned_bot(call.from_user.id, bot_id):
            await call.answer("Not authorized.", show_alert=True)
            return
        await send(
            bot, call,
            f"Confirm removal of bot ID {bot_id}? This permanently removes its platform record and logs.",
            InlineKeyboardMarkup(inline_keyboard=[[
                InlineKeyboardButton(text="Confirm remove", callback_data=f"botremoveconfirm:{bot_id}"),
                InlineKeyboardButton(text="Cancel", callback_data="botremovecancel"),
            ]]),
        )
        await call.answer()

    @router.callback_query(F.data == "botremovecancel")
    async def botremovecancel(call: CallbackQuery):
        await call.answer("Cancelled")

    @router.callback_query(F.data.startswith("botremoveconfirm:"))
    async def botremoveconfirm(call: CallbackQuery, bot: Bot):
        bot_id = int(call.data.split(":")[1])
        if not await get_owned_bot(call.from_user.id, bot_id):
            await call.answer("Not authorized.", show_alert=True)
            return
        await stop_child(bot_id, call.from_user.id)
        await DB.execute("DELETE FROM child_bots WHERE bot_id=$1 AND owner_id=$2", bot_id, call.from_user.id)
        await audit(call.from_user.id, "child_bot_removed", {"bot_id": bot_id})
        await send(bot, call, "Bot removed and its encrypted credential deleted.")
        await call.answer()

    # ---- Info screens ----
    @router.callback_query(F.data == "profile")
    async def profile(call: CallbackQuery, bot: Bot):
        u = await DB.fetchrow("SELECT * FROM users WHERE user_id=$1", call.from_user.id)
        count = await DB.fetchval("SELECT COUNT(*) FROM child_bots WHERE owner_id=$1", call.from_user.id)
        running = await DB.fetchval(
            "SELECT COUNT(*) FROM child_bots WHERE owner_id=$1 AND status='Running'", call.from_user.id
        )
        name = u["display_name"] if u else call.from_user.full_name
        registered = f"{u['registered_at']:%Y-%m-%d %H:%M} UTC" if u else "Not recorded"
        await send(
            bot, call,
            f"User ID: <code>{call.from_user.id}</code>\nName: {esc(name)}\n"
            f"Registered: {registered}\nBots: {count}\nRunning: {running}",
        )
        await call.answer()

    @router.callback_query(F.data == "stats")
    async def stats(call: CallbackQuery, bot: Bot):
        row = await DB.fetchrow(
            "SELECT COUNT(*) AS total, COUNT(*) FILTER (WHERE l.success) AS ok "
            "FROM reaction_logs l JOIN child_bots b USING (bot_id) WHERE b.owner_id=$1",
            call.from_user.id,
        )
        await send(
            bot, call,
            f"Successful reactions: {row['ok']}\nFailed reactions: {row['total'] - row['ok']}",
        )
        await call.answer()

    @router.callback_query(F.data == "settings")
    async def settings(call: CallbackQuery, bot: Bot):
        await send(
            bot, call,
            "Settings: reaction behaviour is configured per connected chat. "
            "Open My Bots, pick a bot, then Reaction Settings.",
        )
        await call.answer()

    @router.callback_query(F.data == "help")
    async def help_handler(call: CallbackQuery, bot: Bot):
        await send(
            bot, call,
            "Help:\n1. Create Bot and submit your BotFather token privately.\n"
            "2. Add the child bot to a group (disable its privacy mode in BotFather) or make it a channel admin.\n"
            "3. Add the chat from My Bots.\n"
            "4. Tune emojis, mode and cooldown under Reaction Settings.\n"
            "Reactions work only where the Bot API and chat permissions allow them.\n"
            "Never share your token with anyone.",
        )
        await call.answer()

    # ---- Admin ----
    @router.callback_query(F.data == "admin")
    async def admin_panel(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id):
            await call.answer("Admin only.", show_alert=True)
            return
        await send(
            bot, call, "Admin Panel",
            InlineKeyboardMarkup(inline_keyboard=[
                [InlineKeyboardButton(text="📊 Overview", callback_data="admin:overview"),
                 InlineKeyboardButton(text="🤖 All Bots", callback_data="admin:bots:0")],
                [InlineKeyboardButton(text="👥 Users", callback_data="admin:users:0"),
                 InlineKeyboardButton(text="📢 Broadcast", callback_data="admin:broadcast")],
                [InlineKeyboardButton(text="🛡️ Audit Logs", callback_data="admin:audit")],
            ]),
        )
        await call.answer()

    @router.callback_query(F.data.startswith("admin:"))
    async def admin_actions(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id):
            await call.answer("Admin only.", show_alert=True)
            return
        action = call.data.split(":")[1]
        if action == "overview":
            users = await DB.fetchval("SELECT COUNT(*) FROM users")
            bots = await DB.fetchval("SELECT COUNT(*) FROM child_bots")
            running = await DB.fetchval("SELECT COUNT(*) FROM child_bots WHERE status='Running'")
            failed = await DB.fetchval("SELECT COUNT(*) FROM child_bots WHERE status='Error'")
            await send(bot, call, f"Users: {users}\nRegistered bots: {bots}\nRunning: {running}\nFailed: {failed}")
        elif action == "bots":
            rows = await DB.fetch(
                "SELECT bot_id,owner_id,username,status,last_error FROM child_bots "
                "ORDER BY created_at DESC LIMIT 30"
            )
            text = "\n".join(
                f"@{esc(r['username'])} | ID {r['bot_id']} | owner {r['owner_id']} | "
                f"{esc(r['status'])} | {esc(r['last_error'] or '-')}"
                for r in rows
            ) or "No bots."
            await send(bot, call, text[:4000])
        elif action == "users":
            rows = await DB.fetch(
                "SELECT user_id,username,display_name FROM users ORDER BY registered_at DESC LIMIT 30"
            )
            text = "\n".join(
                f"{esc(r['display_name'][:40])} (@{esc(r['username'] or '-')}) - {r['user_id']}"
                for r in rows
            ) or "No users."
            await send(bot, call, text[:4000])
        elif action == "audit":
            rows = await DB.fetch(
                "SELECT actor_id,action,created_at FROM audit_logs ORDER BY created_at DESC LIMIT 20"
            )
            text = "\n".join(
                f"{r['created_at']:%Y-%m-%d %H:%M} actor={r['actor_id']} {esc(r['action'])}" for r in rows
            ) or "No audit logs."
            await send(bot, call, text[:4000])
        elif action == "broadcast":
            await send(
                bot, call,
                "Send /broadcast followed by a text message. The platform previews it and asks for "
                "confirmation before delivery.",
            )
        await call.answer()

    @router.callback_query(F.data.startswith("bccancel:"))
    async def bc_cancel(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id):
            await call.answer("Admin only.", show_alert=True)
            return
        PENDING_BROADCASTS.pop(call.data.split(":", 1)[1], None)
        await send(bot, call, "Broadcast cancelled.")
        await call.answer()

    @router.callback_query(F.data.startswith("bcconfirm:"))
    async def bc_confirm(call: CallbackQuery, bot: Bot):
        if not is_admin(call.from_user.id):
            await call.answer("Admin only.", show_alert=True)
            return
        item = PENDING_BROADCASTS.pop(call.data.split(":", 1)[1], None)
        if not item or item[0] != call.from_user.id:
            await call.answer("Expired or unauthorized.", show_alert=True)
            return
        # Answer immediately: callback queries expire, and delivery can take a long time.
        await call.answer("Broadcast started")
        text_content = item[1]
        bid = await DB.fetchval(
            "INSERT INTO broadcasts(admin_id,message_text,status) VALUES($1,$2,'running') RETURNING id",
            call.from_user.id, text_content,
        )
        users = await DB.fetch("SELECT user_id FROM users WHERE NOT blocked")
        ok = fail = 0
        deliveries = []
        blocked_ids = []
        for u in users:
            uid = u["user_id"]
            error = "unknown"
            delivered = False
            for _ in range(2):
                try:
                    await bot.send_message(uid, text_content, parse_mode=None)
                    delivered, error = True, None
                    break
                except TelegramRetryAfter as exc:
                    error = "rate limit"
                    await asyncio.sleep(min(float(exc.retry_after), 30))
                except TelegramForbiddenError as exc:
                    error = safe_error(exc)
                    blocked_ids.append(uid)
                    break
                except Exception as exc:
                    error = safe_error(exc)
                    break
            if delivered:
                ok += 1
            else:
                fail += 1
            deliveries.append((bid, uid, delivered, error))
            await asyncio.sleep(0.05)
        if deliveries:
            await DB.executemany(
                "INSERT INTO broadcast_deliveries(broadcast_id,user_id,success,error_category) "
                "VALUES($1,$2,$3,$4)",
                deliveries,
            )
        if blocked_ids:
            await DB.execute("UPDATE users SET blocked=TRUE WHERE user_id = ANY($1::bigint[])", blocked_ids)
        await DB.execute(
            "UPDATE broadcasts SET status='completed', success_count=$2, failure_count=$3 WHERE id=$1",
            bid, ok, fail,
        )
        await send(bot, call, f"Broadcast complete.\nDelivered: {ok}\nFailed: {fail}")
        await audit(call.from_user.id, "broadcast_completed", {"broadcast_id": bid, "success": ok, "failed": fail})

    # ---- Generic private-chat input (MUST stay last so it never shadows commands) ----
    @router.message(F.chat.type == ChatType.PRIVATE)
    async def private_input(message: Message, bot: Bot):
        if message.from_user is None:
            return
        uid = message.from_user.id
        pending = PENDING_INPUT.get(uid)
        if not pending:
            return
        if message.text and message.text.startswith("/"):
            return  # unknown command; keep waiting
        kind, payload = pending
        PENDING_INPUT.pop(uid, None)
        if kind == "create":
            await handle_token_submission(message, bot)
        elif kind == "addchat":
            await handle_add_chat(message, payload)
        elif kind == "emojis":
            await handle_set_emojis(message, payload)

    async def handle_token_submission(message: Message, bot: Bot):
        uid = message.from_user.id
        token = (message.text or "").strip()
        try:
            await message.delete()
        except Exception as exc:
            log.debug("Ignored non-fatal error (%s)", safe_error(exc))
        if not token or ":" not in token or len(token) > 200 or re.search(r"\s", token):
            await message.answer("Token format looks invalid. Open Create Bot and try again.")
            return
        if not is_admin(uid):
            owned = await DB.fetchval("SELECT COUNT(*) FROM child_bots WHERE owner_id=$1", uid)
            if owned >= MAX_BOTS_PER_USER:
                await message.answer(f"You have reached the limit of {MAX_BOTS_PER_USER} bots.")
                return
        child = Bot(token=token)
        try:
            me = await child.get_me()
        except Exception as exc:
            await message.answer(f"Token validation failed ({esc(safe_error(exc))}). Check it with BotFather and try again.")
            return
        finally:
            await child.session.close()
        try:
            await ensure_user(message.from_user)
            await DB.execute(
                "INSERT INTO child_bots(bot_id,owner_id,username,name,token_enc,status,autostart) "
                "VALUES($1,$2,$3,$4,$5,'Stopped',TRUE)",
                me.id, uid, me.username or str(me.id), me.first_name or "Telegram bot", encrypt_token(token),
            )
        except asyncpg.UniqueViolationError:
            await message.answer("This bot is already registered on the platform.")
            return
        except Exception as exc:
            log.warning("Child registration failed (%s)", safe_error(exc))
            await message.answer("Could not save this bot. Please try again later.")
            return
        await audit(uid, "child_bot_registered", {"bot_id": me.id, "username": me.username})
        status = await start_child(me.id, uid)
        await message.answer(
            f"Validated @{esc(me.username or me.id)} (ID: {me.id}). Runtime status: {esc(status)}.",
            reply_markup=bot_keyboard(me.id),
        )
        await notify_admin(
            bot,
            f"New child bot registered: @{me.username or me.id} (ID {me.id}) by user {uid}",
        )

    async def handle_add_chat(message: Message, bot_id: int):
        uid = message.from_user.id
        row = await get_owned_bot(uid, bot_id)
        if not row:
            await message.answer("Bot not found.")
            return
        target = None
        origin = message.forward_origin
        if origin is not None:
            origin_chat = getattr(origin, "chat", None) or getattr(origin, "sender_chat", None)
            if origin_chat is not None:
                target = origin_chat.id
        if target is None:
            text = (message.text or "").strip()
            if text.startswith("@"):
                target = text
            else:
                try:
                    target = int(text)
                except ValueError:
                    target = None
        if target is None:
            await message.answer("Send a numeric chat ID, an @username, or forward a message from the chat.")
            return
        child = Bot(token=decrypt_token(row["token_enc"]))
        try:
            chat = await child.get_chat(target)
            member = await child.get_chat_member(chat.id, bot_id)
            if member.status not in (
                ChatMemberStatus.MEMBER,
                ChatMemberStatus.ADMINISTRATOR,
                ChatMemberStatus.CREATOR,
            ):
                await message.answer("The child bot is not a member of that chat. Add it first, then try again.")
                return
            await DB.execute(
                """
                INSERT INTO connected_chats(bot_id,chat_id,title,chat_type,emojis)
                VALUES($1,$2,$3,$4,$5)
                ON CONFLICT (bot_id, chat_id) DO UPDATE SET title=EXCLUDED.title, enabled=TRUE
                """,
                bot_id, chat.id, chat.title or chat.full_name or str(chat.id),
                str(getattr(chat.type, "value", chat.type)), DEFAULT_EMOJIS,
            )
            await message.answer(
                f"Connected chat verified: {esc(chat.title or chat.id)}. "
                "Send a message there to test the reaction.",
                reply_markup=bot_keyboard(bot_id),
            )
        except Exception as exc:
            await message.answer(f"Could not verify/add chat ({esc(safe_error(exc))}). Check the chat and the bot's access.")
        finally:
            await child.session.close()

    async def handle_set_emojis(message: Message, payload):
        uid = message.from_user.id
        bot_id, chat_id = payload
        if not await get_owned_bot(uid, bot_id):
            await message.answer("Bot not found.")
            return
        emojis = parse_emojis(message.text or "")
        if not emojis:
            await message.answer("No valid emoji found. Open Reaction Settings and try again.")
            return
        await DB.execute(
            "UPDATE connected_chats SET emojis=$3 WHERE bot_id=$1 AND chat_id=$2",
            bot_id, chat_id, emojis,
        )
        await message.answer(f"Emojis updated: {' '.join(esc(e) for e in emojis)}")

    return router


# ----------------------------------------------------------------------------
# Web server (health + dashboard)
# ----------------------------------------------------------------------------
async def health(request: web.Request) -> web.Response:
    global LAST_HEALTH_CHECK
    LAST_HEALTH_CHECK = now_iso()
    return web.json_response({"status": "ok", "web_server": WEB_STATE, "timestamp": LAST_HEALTH_CHECK})


async def api_status(request: web.Request) -> web.Response:
    global LAST_HEALTH_CHECK
    LAST_HEALTH_CHECK = now_iso()
    total = running = None
    if DB is not None:
        try:
            total = await DB.fetchval("SELECT COUNT(*) FROM child_bots")
            running = await DB.fetchval("SELECT COUNT(*) FROM child_bots WHERE status='Running'")
        except Exception:
            total = running = None
    return web.json_response({
        "master_bot": MASTER_STATE,
        "web_server": WEB_STATE,
        "registered_child_bots": total,
        "running_child_bots": running,
        "uptime_seconds": int(time.time() - START_TIME),
        "last_health_check": LAST_HEALTH_CHECK,
    })


DASHBOARD_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Reaction Platform Status</title><style>
*{box-sizing:border-box}body{margin:0;background:#0b1220;color:#e8eefc;font-family:system-ui,-apple-system,sans-serif;padding:24px}
main{max-width:760px;margin:auto}.card{background:#131e31;border:1px solid #263650;border-radius:18px;padding:22px;margin:14px 0}
h1{font-size:clamp(24px,5vw,36px);margin:0 0 8px}.muted{color:#9aabc7}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.label{color:#9aabc7;font-size:13px}.value{font-size:23px;font-weight:700;margin-top:7px}
button{border:0;background:#5b8cff;color:#fff;padding:12px 18px;border-radius:10px;font-weight:700;cursor:pointer}pre{white-space:pre-wrap;word-break:break-word}
</style></head><body><main><div class="card"><div class="muted">RENDER SERVICE HEALTH</div><h1>Telegram Reaction Platform</h1><p class="muted">Live operational status. No credentials or private user data are exposed.</p><button onclick="refresh()">Refresh Status</button> <span id="updated" class="muted"></span></div>
<div class="grid"><div class="card"><div class="label">Master Telegram Bot</div><div class="value" id="master">Loading…</div></div>
<div class="card"><div class="label">Web Server</div><div class="value" id="web">Loading…</div></div>
<div class="card"><div class="label">Registered Child Bots</div><div class="value" id="total">—</div></div>
<div class="card"><div class="label">Running Child Bots</div><div class="value" id="running">—</div></div>
<div class="card"><div class="label">Application Uptime</div><div class="value" id="uptime">—</div></div></div>
<div class="card"><div class="label">Last successful status request</div><pre id="last">—</pre></div></main>
<script>
async function refresh(){try{const r=await fetch('/api/status',{cache:'no-store'});if(!r.ok)throw Error('HTTP '+r.status);const d=await r.json();
document.getElementById('master').textContent=d.master_bot;document.getElementById('web').textContent=d.web_server;
document.getElementById('total').textContent=d.registered_child_bots??'Unavailable';document.getElementById('running').textContent=d.running_child_bots??'Unavailable';
document.getElementById('uptime').textContent=Math.floor((d.uptime_seconds||0)/3600)+'h '+Math.floor(((d.uptime_seconds||0)%3600)/60)+'m';
document.getElementById('last').textContent=d.last_health_check||'—';document.getElementById('updated').textContent='Updated just now';
}catch(e){document.getElementById('updated').textContent='Status fetch failed';}}
refresh();setInterval(refresh,20000);
</script></body></html>"""


async def dashboard(request: web.Request) -> web.Response:
    return web.Response(text=DASHBOARD_HTML, content_type="text/html")


async def start_web_server() -> None:
    global WEB_RUNNER, WEB_STATE
    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/health", health)
    app.router.add_get("/api/status", api_status)
    WEB_RUNNER = web.AppRunner(app, access_log=None)
    await WEB_RUNNER.setup()
    site = web.TCPSite(WEB_RUNNER, host="0.0.0.0", port=PORT)
    await site.start()
    WEB_STATE = "Running"
    log.info("Web server listening on 0.0.0.0:%s", PORT)


# ----------------------------------------------------------------------------
# Entrypoint: everything shares ONE asyncio event loop
# ----------------------------------------------------------------------------
async def main() -> None:
    global MASTER_STATE, WEB_STATE, MASTER_USERNAME, SHUTTING_DOWN
    validate_config()
    init_crypto()

    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop_event.set)
        except (NotImplementedError, RuntimeError) as exc:
            log.debug("Ignored non-fatal error (%s)", safe_error(exc))

    master = Bot(token=BOT_TOKEN, default=DefaultBotProperties(parse_mode=ParseMode.HTML))
    background: list = []
    polling_task: Optional[asyncio.Task] = None
    exit_error: Optional[BaseException] = None

    try:
        # Bind the HTTP port first so Render's port scan succeeds immediately.
        await start_web_server()
        await init_db()

        try:
            me = await master.get_me()
            MASTER_USERNAME = me.username
        except Exception as exc:
            MASTER_STATE = "Error"
            raise RuntimeError(
                f"Master bot initialization failed ({safe_error(exc)}). Check BOT_TOKEN."
            ) from None

        dp = Dispatcher()
        dp.include_router(build_master_router())
        try:
            await master.set_my_commands([
                BotCommand(command="start", description="Open platform"),
                BotCommand(command="cancel", description="Cancel the current action"),
                BotCommand(command="broadcast", description="Admin: preview a text broadcast"),
            ])
        except Exception as exc:
            log.warning("Could not set bot commands (%s)", safe_error(exc))

        # Statuses from a previous process are stale by definition.
        await DB.execute("UPDATE child_bots SET status='Stopped' WHERE status IN ('Running','Starting')")
        background.append(asyncio.create_task(resume_child_bots(), name="resume-child-bots"))
        background.append(asyncio.create_task(maintenance_loop(), name="maintenance"))

        MASTER_STATE = "Running"
        log.info("Master bot @%s starting polling", MASTER_USERNAME)
        polling_task = asyncio.create_task(
            dp.start_polling(
                master,
                allowed_updates=dp.resolve_used_update_types(),
                handle_signals=False,
            ),
            name="master-polling",
        )
        stop_waiter = asyncio.create_task(stop_event.wait(), name="stop-waiter")
        background.append(stop_waiter)

        done, _ = await asyncio.wait({polling_task, stop_waiter}, return_when=asyncio.FIRST_COMPLETED)
        if polling_task in done and not polling_task.cancelled() and polling_task.exception():
            MASTER_STATE = "Error"
            exit_error = polling_task.exception()
            log.error("Master bot stopped unexpectedly (%s)", safe_error(exit_error))
        else:
            log.info("Shutdown requested")
    finally:
        SHUTTING_DOWN = True
        if MASTER_STATE != "Error":
            MASTER_STATE = "Stopped"

        to_cancel = [t for t in background if not t.done()]
        if polling_task is not None and not polling_task.done():
            to_cancel.append(polling_task)
        for task in to_cancel:
            task.cancel()
        if to_cancel:
            await asyncio.gather(*to_cancel, return_exceptions=True)

        child_tasks = [r["task"] for r in list(CHILD_RUNTIMES.values())]
        for task in child_tasks:
            task.cancel()
        if child_tasks:
            await asyncio.gather(*child_tasks, return_exceptions=True)

        if WEB_RUNNER is not None:
            try:
                await WEB_RUNNER.cleanup()
            except Exception as exc:
                log.debug("Ignored non-fatal error (%s)", safe_error(exc))
        WEB_STATE = "Stopped"

        try:
            await master.session.close()
        except Exception as exc:
            log.debug("Ignored non-fatal error (%s)", safe_error(exc))
        if DB is not None:
            try:
                await DB.close()
            except Exception as exc:
                log.debug("Ignored non-fatal error (%s)", safe_error(exc))

    if exit_error is not None:
        raise exit_error


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Interrupted")
    except Exception as exc:
        # Never print exception text; it may contain secrets.
        log.error("Application startup/runtime failed: %s", safe_error(exc))
        if isinstance(exc, RuntimeError):
            log.error("%s", exc)
        sys.exit(1)
