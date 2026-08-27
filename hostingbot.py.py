"""Telegram bot for hosting and managing multiple Python bots.

Configuration:
BOT_TOKEN = "8985769471:AAElWicQyPR1SDCE2hS8B2ZL-fBCK9uzesI"  
ADMIN_IDS = {1808235854}  

The managed bots are kept in ./bots. Each uploaded ZIP should contain a
main.py file (or another top-level .py file) and may contain requirements.txt.
Dependencies are installed into a private .venv inside that bot directory.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import os
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode
from aiogram.filters import CommandStart
from aiogram.types import InlineKeyboardButton, InlineKeyboardMarkup


# ── CONFIG ────────────────────────────────────────────────────────────────────

BOT_TOKEN = "8985769471:AAElWicQyPR1SDCE2hS8B2ZL-fBCK9uzesI"  # <-- TOKEN SET

ADMIN_IDS = {1808235854}  # <-- ADMIN ID SET

BOTS_DIR = Path(os.getenv("BOTS_DIR", "bots"))
BOTS_DIR.mkdir(parents=True, exist_ok=True)

MAX_ZIP_FILES = 500
MAX_UNCOMPRESSED_BYTES = 50 * 1024 * 1024
MAX_LOG_CHARS = 800
BOT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,49}$")

bot = Bot(
    token=BOT_TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)
dp = Dispatcher()
router = Router()

# name -> subprocess.Popen
processes: dict[str, subprocess.Popen[bytes]] = {}


# ── HELPERS ──────────────────────────────────────────────────────────────────

def is_admin(uid: int) -> bool:
    return uid in ADMIN_IDS


def get_bot_list() -> list[str]:
    return sorted(
        directory.name
        for directory in BOTS_DIR.iterdir()
        if directory.is_dir() and BOT_NAME_RE.fullmatch(directory.name)
    )


def get_process(name: str) -> subprocess.Popen[bytes] | None:
    process = processes.get(name)
    if process is not None and process.poll() is not None:
        processes.pop(name, None)
        return None
    return process


def get_status(name: str) -> str:
    return "🟢 Running" if get_process(name) is not None else "⚪ Stopped"


def get_log_file(name: str) -> Path:
    return BOTS_DIR / name / "logs.txt"


def display(value: object) -> str:
    """Escape dynamic values before putting them in Telegram HTML."""
    return html.escape(str(value), quote=False)


def callback_name(data: str, prefix: str) -> str:
    return data[len(prefix):]


def bot_directory(name: str) -> Path:
    if not BOT_NAME_RE.fullmatch(name):
        raise ValueError("Invalid bot name")
    return BOTS_DIR / name


def find_entrypoint(bot_dir: Path) -> Path | None:
    main_file = bot_dir / "main.py"
    if main_file.is_file():
        return main_file

    candidates = sorted(
        path for path in bot_dir.glob("*.py") if path.is_file() and path.name != "logs.txt"
    )
    return candidates[0] if candidates else None


def python_for_bot(bot_dir: Path) -> Path:
    if os.name == "nt":
        venv_python = bot_dir / ".venv" / "Scripts" / "python.exe"
    else:
        venv_python = bot_dir / ".venv" / "bin" / "python"
    return venv_python if venv_python.is_file() else Path(sys.executable)


def requirements_digest(requirements: Path) -> str:
    return hashlib.sha256(requirements.read_bytes()).hexdigest()


def provision_environment(bot_dir: Path) -> Path:
    """Create/update a private virtual environment when requirements exist."""
    requirements = bot_dir / "requirements.txt"
    if not requirements.is_file():
        return Path(sys.executable)

    venv_python = (
        bot_dir / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else bot_dir / ".venv" / "bin" / "python"
    )
    marker = bot_dir / ".venv.requirements.sha256"
    digest = requirements_digest(requirements)

    if not venv_python.is_file():
        subprocess.run(
            [sys.executable, "-m", "venv", str(bot_dir / ".venv")],
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )

    existing_digest = marker.read_text(encoding="utf-8").strip() if marker.is_file() else None
    if existing_digest != digest:
        subprocess.run(
            [str(venv_python), "-m", "pip", "install", "-r", str(requirements)],
            cwd=bot_dir,
            check=True,
            capture_output=True,
            text=True,
            timeout=600,
        )
        marker.write_text(digest + "\n", encoding="utf-8")

    return venv_python


def safe_extract_zip(zip_path: Path, destination: Path) -> None:
    """Extract a ZIP without allowing traversal, symlinks, or ZIP bombs."""
    destination = destination.resolve()
    file_count = 0
    extracted_bytes = 0

    with zipfile.ZipFile(zip_path) as archive:
        for info in archive.infolist():
            raw_name = info.filename.replace("\\", "/")
            member = PurePosixPath(raw_name)

            if member.is_absolute() or ".." in member.parts:
                raise ValueError(f"Unsafe ZIP path: {info.filename}")

            # ZIP symlinks can escape the extraction directory after extraction.
            mode = (info.external_attr >> 16) & 0o170000
            if mode == stat.S_IFLNK:
                raise ValueError(f"Symlinks are not allowed: {info.filename}")

            file_count += 1
            if file_count > MAX_ZIP_FILES:
                raise ValueError(f"ZIP contains more than {MAX_ZIP_FILES} files")

            target = (destination / Path(*member.parts)).resolve()
            if target != destination and destination not in target.parents:
                raise ValueError(f"Unsafe ZIP path: {info.filename}")

            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue

            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, target.open("wb") as output:
                while True:
                    chunk = source.read(1024 * 1024)
                    if not chunk:
                        break
                    extracted_bytes += len(chunk)
                    if extracted_bytes > MAX_UNCOMPRESSED_BYTES:
                        raise ValueError(
                            f"ZIP expands beyond {MAX_UNCOMPRESSED_BYTES // (1024 * 1024)} MB"
                        )
                    output.write(chunk)


def copy_payload(extracted: Path, bot_dir: Path) -> None:
    """Flatten the common `bot-name/main.py` ZIP layout."""
    children = list(extracted.iterdir())
    source = children[0] if len(children) == 1 and children[0].is_dir() else extracted

    for item in source.iterdir():
        target = bot_dir / item.name
        if item.is_symlink():
            raise ValueError("Symlinks are not allowed in uploaded bots")
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def start_process(name: str, bot_dir: Path, python_path: Path) -> subprocess.Popen[bytes]:
    entrypoint = find_entrypoint(bot_dir)
    if entrypoint is None:
        raise FileNotFoundError("No .py file found in the bot ZIP")

    log_file = get_log_file(name)
    log_file.parent.mkdir(parents=True, exist_ok=True)
    log_handle = log_file.open("ab")
    environment = os.environ.copy()
    environment["PYTHONUNBUFFERED"] = "1"

    try:
        process = subprocess.Popen(
            [str(python_path), "-u", str(entrypoint)],
            cwd=bot_dir,
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            env=environment,
            start_new_session=(os.name != "nt"),
        )
    finally:
        # The child has its own descriptor after Popen; the parent must close ours.
        log_handle.close()

    processes[name] = process
    return process


async def terminate_process(name: str) -> bool:
    process = get_process(name)
    if process is None:
        processes.pop(name, None)
        return False

    try:
        if os.name != "nt":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()

        try:
            await asyncio.to_thread(process.wait, 5)
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                os.killpg(process.pid, signal.SIGKILL)
            else:
                process.kill()
            await asyncio.to_thread(process.wait)
    finally:
        processes.pop(name, None)
    return True


async def send_error(message: types.Message, error: Exception) -> None:
    # Do not expose a traceback or unescaped markup to Telegram.
    await message.edit_text(f"❌ Error: <code>{display(str(error)[:1500])}</code>")


# ── KEYBOARDS ────────────────────────────────────────────────────────────────

def main_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="📋 List Bots", callback_data="list")],
            [InlineKeyboardButton(text="➕ Add Bot", callback_data="add")],
            [InlineKeyboardButton(text="📊 Stats", callback_data="stats")],
        ]
    )


def back_kb() -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [InlineKeyboardButton(text="🔙 Back", callback_data="back")]
        ]
    )


def bot_kb(name: str) -> InlineKeyboardMarkup:
    running = get_process(name) is not None
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="⏹ Stop" if running else "▶️ Start",
                    callback_data=f"stop_{name}" if running else f"start_{name}",
                ),
                InlineKeyboardButton(text="🔄 Restart", callback_data=f"restart_{name}"),
            ],
            [
                InlineKeyboardButton(text="📄 Logs", callback_data=f"logs_{name}"),
                InlineKeyboardButton(text="🗑 Delete", callback_data=f"delete_{name}"),
            ],
            [InlineKeyboardButton(text="🔙 Back", callback_data="list")],
        ]
    )


def delete_confirm_kb(name: str) -> InlineKeyboardMarkup:
    return InlineKeyboardMarkup(
        inline_keyboard=[
            [
                InlineKeyboardButton(
                    text="✅ Yes, delete",
                    callback_data=f"delete_confirm_{name}",
                ),
                InlineKeyboardButton(
                    text="Cancel",
                    callback_data=f"delete_cancel_{name}",
                ),
            ]
        ]
    )


# ── COMMANDS ─────────────────────────────────────────────────────────────────

@router.message(CommandStart())
async def start_cmd(message: types.Message) -> None:
    if not is_admin(message.from_user.id):
        await message.answer("❌ Unauthorized")
        return
    await message.answer(
        "🤖 <b>Hosting Bot</b>\n\n"
        "Upload a .zip file to add a bot.\n"
        "Use the buttons below to manage bots.",
        reply_markup=main_kb(),
    )


@router.message(F.document)
async def handle_upload(message: types.Message) -> None:
    if not is_admin(message.from_user.id):
        return

    document = message.document
    filename = document.file_name or ""
    if not filename.lower().endswith(".zip"):
        await message.answer("❌ Upload a .zip file only.")
        return

    name = Path(filename).stem
    if not BOT_NAME_RE.fullmatch(name):
        await message.answer(
            "❌ Invalid file name. Use 1–50 letters, numbers, hyphens, or underscores."
        )
        return

    bot_dir = bot_directory(name)
    if bot_dir.exists():
        await message.answer(f"❌ Bot <b>{display(name)}</b> already exists.")
        return

    status_message = await message.answer("📦 Downloading and checking ZIP…")
    staging_dir: Path | None = None

    try:
        telegram_file = await bot.get_file(document.file_id)
        data: BinaryIO = await bot.download_file(telegram_file.file_path)

        with tempfile.TemporaryDirectory(prefix=".bot-upload-", dir=BOTS_DIR) as temp_dir:
            staging_dir = Path(temp_dir)
            zip_path = staging_dir / filename
            zip_path.write_bytes(data.read())
            extracted_dir = staging_dir / "extracted"
            extracted_dir.mkdir()
            safe_extract_zip(zip_path, extracted_dir)

            bot_dir.mkdir()
            copy_payload(extracted_dir, bot_dir)

        await status_message.edit_text(
            f"✅ Bot <b>{display(name)}</b> added!\n"
            f"Files: {len(list(bot_dir.iterdir()))}",
            reply_markup=bot_kb(name),
        )
    except Exception as error:
        if bot_dir.exists():
            shutil.rmtree(bot_dir, ignore_errors=True)
        await send_error(status_message, error)


# ── CALLBACKS ───────────────────────────────────────────────────────────────

@router.callback_query(F.data == "list")
async def list_bots(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    bots = get_bot_list()
    if not bots:
        await callback.message.edit_text("No bots found.", reply_markup=back_kb())
        await callback.answer()
        return

    text = "📋 <b>Bot List</b>\n\n"
    keyboard = []
    for name in bots:
        text += f"• <b>{display(name)}</b> {get_status(name)}\n"
        keyboard.append(
            [InlineKeyboardButton(text=f"📦 {name}", callback_data=f"bot_{name}")]
        )
    keyboard.append([InlineKeyboardButton(text="🔙 Back", callback_data="back")])

    await callback.message.edit_text(
        text, reply_markup=InlineKeyboardMarkup(inline_keyboard=keyboard)
    )
    await callback.answer()


@router.callback_query(F.data.startswith("bot_"))
async def bot_detail(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "bot_")
    if name not in get_bot_list():
        await callback.message.edit_text("❌ Bot not found.", reply_markup=back_kb())
        await callback.answer()
        return

    process = get_process(name)
    pid = process.pid if process is not None else "—"
    text = (
        f"📦 <b>{display(name)}</b>\n"
        "━━━━━━━━━━━━━━━━\n"
        f"Status: {get_status(name)}\n"
        f"PID: {pid}\n"
    )
    await callback.message.edit_text(text, reply_markup=bot_kb(name))
    await callback.answer()


@router.callback_query(F.data.startswith("start_"))
async def start_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "start_")
    try:
        bot_dir = bot_directory(name)
    except ValueError:
        await callback.answer("❌ Invalid bot name")
        return

    if not bot_dir.is_dir():
        await callback.message.edit_text("❌ Bot not found.", reply_markup=back_kb())
        await callback.answer()
        return
    if get_process(name) is not None:
        await callback.message.edit_text(
            "⚠️ Already running.", reply_markup=bot_kb(name)
        )
        await callback.answer()
        return

    await callback.message.edit_text(
        f"⏳ Starting <b>{display(name)}</b>…", reply_markup=bot_kb(name)
    )
    try:
        python_path = await asyncio.to_thread(provision_environment, bot_dir)
        await asyncio.to_thread(start_process, name, bot_dir, python_path)
        await callback.message.edit_text(
            f"✅ <b>{display(name)}</b> started!", reply_markup=bot_kb(name)
        )
    except Exception as error:
        await send_error(callback.message, error)
        await callback.message.edit_reply_markup(reply_markup=bot_kb(name))
    await callback.answer()


@router.callback_query(F.data.startswith("stop_"))
async def stop_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "stop_")
    try:
        stopped = await terminate_process(name)
        text = f"⏹ <b>{display(name)}</b> stopped!" if stopped else "⚠️ Not running."
        await callback.message.edit_text(text, reply_markup=bot_kb(name))
    except Exception as error:
        await send_error(callback.message, error)
        await callback.message.edit_reply_markup(reply_markup=bot_kb(name))
    await callback.answer()


@router.callback_query(F.data.startswith("restart_"))
async def restart_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "restart_")
    try:
        bot_dir = bot_directory(name)
        if not bot_dir.is_dir():
            raise FileNotFoundError("Bot not found")

        await callback.message.edit_text(
            f"🔄 Restarting <b>{display(name)}</b>…", reply_markup=bot_kb(name)
        )
        await terminate_process(name)
        python_path = await asyncio.to_thread(provision_environment, bot_dir)
        await asyncio.to_thread(start_process, name, bot_dir, python_path)
        await callback.message.edit_text(
            f"✅ <b>{display(name)}</b> restarted!", reply_markup=bot_kb(name)
        )
    except Exception as error:
        await send_error(callback.message, error)
        await callback.message.edit_reply_markup(reply_markup=bot_kb(name))
    await callback.answer()


@router.callback_query(F.data.startswith("logs_"))
async def view_logs(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "logs_")
    log_file = get_log_file(name)
    if not log_file.is_file():
        await callback.message.edit_text("📄 No logs yet.", reply_markup=bot_kb(name))
        await callback.answer()
        return

    content = log_file.read_text(encoding="utf-8", errors="replace")[-MAX_LOG_CHARS:]
    if not content:
        content = "(empty)"
    await callback.message.edit_text(
        f"📄 <b>Logs: {display(name)}</b>\n\n"
        f"<pre>{display(content)}</pre>",
        reply_markup=bot_kb(name),
    )
    await callback.answer()


@router.callback_query(F.data.startswith("delete_confirm_"))
async def confirm_delete_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "delete_confirm_")
    try:
        bot_dir = bot_directory(name)
        await terminate_process(name)
        if bot_dir.is_dir():
            shutil.rmtree(bot_dir)
        await callback.message.edit_text(
            f"🗑 <b>{display(name)}</b> deleted!", reply_markup=back_kb()
        )
    except Exception as error:
        await send_error(callback.message, error)
    await callback.answer()


@router.callback_query(F.data.startswith("delete_cancel_"))
async def cancel_delete_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "delete_cancel_")
    await callback.message.edit_text(
        f"📦 <b>{display(name)}</b>", reply_markup=bot_kb(name)
    )
    await callback.answer()


@router.callback_query(F.data.startswith("delete_"))
async def delete_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    name = callback_name(callback.data, "delete_")
    if name not in get_bot_list():
        await callback.message.edit_text("❌ Bot not found.", reply_markup=back_kb())
        await callback.answer()
        return

    await callback.message.edit_text(
        f"⚠️ Delete <b>{display(name)}</b> and all its files?",
        reply_markup=delete_confirm_kb(name),
    )
    await callback.answer()


@router.callback_query(F.data == "add")
async def add_bot(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    await callback.message.edit_text(
        "📦 <b>Add a Bot</b>\n\n"
        "Upload a <b>.zip</b> file containing your bot's code.\n\n"
        "Requirements:\n"
        "• Include <code>main.py</code> or another top-level <code>.py</code> file\n"
        "• Put dependencies in <code>requirements.txt</code>\n"
        "• Use a simple ZIP filename such as <code>weather_bot.zip</code>",
        reply_markup=back_kb(),
    )
    await callback.answer()


@router.callback_query(F.data == "stats")
async def stats(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    total = len(get_bot_list())
    running = sum(get_process(name) is not None for name in get_bot_list())
    await callback.message.edit_text(
        "📊 <b>Hosting Stats</b>\n"
        "━━━━━━━━━━━━━━━━\n"
        f"Total Bots: {total}\n"
        f"Running: {running}\n"
        f"Stopped: {total - running}\n"
        "━━━━━━━━━━━━━━━━\n"
        f"Bots Dir: <code>{display(BOTS_DIR.resolve())}</code>",
        reply_markup=back_kb(),
    )
    await callback.answer()


@router.callback_query(F.data == "back")
async def back(callback: types.CallbackQuery) -> None:
    if not is_admin(callback.from_user.id):
        await callback.answer("❌ Unauthorized")
        return

    await callback.message.edit_text(
        "🤖 <b>Hosting Bot</b>\n\nUpload a .zip file to add a bot.",
        reply_markup=main_kb(),
    )
    await callback.answer()


# ── MAIN ─────────────────────────────────────────────────────────────────────

async def main() -> None:
    dp.include_router(router)
    await bot.delete_webhook(drop_pending_updates=True)
    print("🤖 Hosting Bot started")
    print(f"Admins: {sorted(ADMIN_IDS)}")
    print(f"Bots directory: {BOTS_DIR.resolve()}")
    try:
        await dp.start_polling(bot)
    finally:
        for name in list(processes):
            await terminate_process(name)
        await bot.session.close()


if __name__ == "__main__":
    asyncio.run(main())