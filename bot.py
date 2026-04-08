import os
import sys
import asyncio
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    filters,
    ContextTypes,
)

load_dotenv()

# ── Bootstrap VSec agent ───────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pentest_agent import agent, save_report, G, B, RS
from message_utils import convert_langchain_messages, get_last_ai_response, build_langchain_messages
from vsec.api.storage import init_db, get_db_path
from vsec.api.repositories import get_session_repo

# Initialize database on startup
init_db()

BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")

# ── Per-user sessions (chat_id -> session_id mapping) ─────────────────────────
# Now persistent via SQLite!
user_sessions: dict[int, str] = {}

# ── Helpers ───────────────────────────────────────────────────────────────────
def split_message(text: str, limit: int = 4000) -> list[str]:
    parts = []
    while len(text) > limit:
        split_at = text.rfind("\n", 0, limit)
        if split_at == -1:
            split_at = limit
        parts.append(text[:split_at])
        text = text[split_at:].lstrip("\n")
    if text:
        parts.append(text)
    return parts


async def run_agent(chat_id: int, user_input: str) -> str:
    repo = get_session_repo()
    
    # Get or create session for this user
    if chat_id not in user_sessions:
        session = repo.create(model="claude-haiku-4-5")
        user_sessions[chat_id] = session["id"]
        session_id = session["id"]
    else:
        session_id = user_sessions[chat_id]
    
    # Get existing messages from database
    session_data = repo.get(session_id)
    if not session_data:
        # Session was deleted, create new
        session = repo.create(model="claude-haiku-4-5")
        user_sessions[chat_id] = session["id"]
        session_id = session["id"]
        session_data = session
    
    # Add user message to database
    repo.add_message(session_id, "user", user_input)
    
    # Re-fetch with updated messages
    session_data = repo.get(session_id)
    messages_dicts = session_data.get("messages", [])
    
    # Convert to LangChain format for agent
    langchain_messages = build_langchain_messages(messages_dicts)
    
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: agent.invoke(
            {"messages": langchain_messages},
            config={"callbacks": []},
        )
    )
    
    # Extract response properly using the utility function
    response = get_last_ai_response(result["messages"])
    
    if not response:
        response = "No response generated."
    
    # Convert all messages back to dict format and save to database
    updated_messages = convert_langchain_messages(result["messages"])
    
    # Update session with full message history in database
    for msg in updated_messages:
        # Messages are already in the session from the loop above
        pass
    
    # Update the session's messages field directly
    repo.update(session_id, messages=updated_messages)

    return response


# ── Handlers ──────────────────────────────────────────────────────────────────
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "⚡ *VSec — AI Penetration Testing Agent*\n\n"
        "Send me a target URL to start recon:\n"
        "`https://target.com`\n\n"
        "Commands:\n"
        "/new — Start fresh engagement\n"
        "/help — Show this message\n\n"
        "⚠️ Only use on systems you own or have written authorization to test.",
        parse_mode="Markdown"
    )


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "⚡ *VSec Commands*\n\n"
        "Send a target URL to start:\n"
        "`https://target.com`\n\n"
        "Or ask anything:\n"
        "`what CVEs are available for nginx?`\n"
        "`run nmap on 192.168.1.1`\n"
        "`check if /.env is exposed on target.com`\n\n"
        "/new — Clear conversation history\n"
        "/start — Welcome message",
        parse_mode="Markdown"
    )


async def new_session(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = update.effective_chat.id
    repo = get_session_repo()
    
    # Delete old session if exists
    if chat_id in user_sessions:
        repo.delete(user_sessions[chat_id])
    
    # Create new session
    session = repo.create(model="claude-haiku-4-5")
    user_sessions[chat_id] = session["id"]
    
    await update.message.reply_text(
        "🔄 Session cleared. New engagement started.\n"
        "Send me a target URL to begin."
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id    = update.effective_chat.id
    user_input = update.message.text.strip()

    if not user_input:
        return

    status_msg = await update.message.reply_text(
        "⚙️ *VSec is running...*\n"
        "_This may take 30–90 seconds_",
        parse_mode="Markdown"
    )

    try:
        response = await run_agent(chat_id, user_input)

        await status_msg.delete()

        # Auto-save report
        if any(kw in response for kw in ["[REPORT]", "[RECON]", "Finding #", "Severity", "PENETRATION TEST"]):
            target   = user_input if "http" in user_input else "unknown"
            filepath = save_report(target, response)
            response += f"\n\n📁 Report saved: `{os.path.basename(filepath)}`"

        # Send in chunks
        for chunk in split_message(response):
            try:
                await update.message.reply_text(chunk, parse_mode="Markdown")
            except Exception:
                # If markdown parsing fails, send as plain text
                await update.message.reply_text(chunk)

    except Exception as e:
        await status_msg.delete()
        await update.message.reply_text(f"❌ Error: {str(e)[:200]}")


# ── Run ────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    if not BOT_TOKEN:
        raise ValueError("TELEGRAM_BOT_TOKEN not set in .env")

    print(f"\n  {G}{B}VSec Telegram Bot starting...{RS}")
    print(f"  {G}✔{RS} Token loaded")
    print(f"  {G}✔{RS} Database: {get_db_path()}")

    app = ApplicationBuilder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help",  help_command))
    app.add_handler(CommandHandler("new",   new_session))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print(f"  {G}✔{RS} Bot is running. Press Ctrl+C to stop.\n")
    app.run_polling()
