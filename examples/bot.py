"""
Telegram bot with full prompt injection protection pipeline.

Flow: User message -> Auth -> Rate limit -> Input filter -> LLM -> Output filter -> User
"""

import asyncio
import yaml
from pathlib import Path

from telegram import Update
from telegram.ext import (
    ApplicationBuilder,
    CommandHandler,
    MessageHandler,
    ContextTypes,
    filters,
)

from prompt_guard import scan_input, scan_output, UserManager, AuditLogger
from llm_client import LLMClient


def load_config(path: str = "config.yaml") -> dict:
    with open(path) as f:
        return yaml.safe_load(f)


CONFIG = load_config()

# Initialize components
audit = AuditLogger(
    audit_file=CONFIG["logging"]["audit_file"],
    log_level=CONFIG["logging"]["log_level"],
)

user_mgr = UserManager(
    allowed_users=CONFIG["telegram"].get("allowed_users") or None,
    blocked_users=CONFIG["telegram"].get("blocked_users") or None,
    max_per_minute=CONFIG["rate_limit"]["max_messages_per_minute"],
    max_per_hour=CONFIG["rate_limit"]["max_messages_per_hour"],
    auto_block_score=CONFIG["threat"]["auto_block_score"],
    block_penalty=CONFIG["threat"]["block_penalty"],
    decay_per_hour=CONFIG["threat"]["decay_per_hour"],
)

llm = LLMClient(
    base_url=CONFIG["ollama"]["base_url"],
    model=CONFIG["ollama"]["model"],
    system_prompt=CONFIG["system_prompt"],
)

ALLOWED_DIRS = CONFIG.get("allowed_directories", [])
CANARY = CONFIG["canary_token"]


async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Bot is running. Send me a message and I'll respond via the LLM.\n"
        "Use /status to check your rate limit stats."
    )


async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    stats = user_mgr.get_stats(user_id)
    await update.message.reply_text(
        f"Messages last hour: {stats['messages_last_hour']}\n"
        f"Threat score: {stats['threat_score']}\n"
        f"Total blocked: {stats['total_blocked']}"
    )


async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    user_id = user.id
    username = user.username
    text = update.message.text

    if not text:
        return

    # --- Log receipt ---
    audit.log_message_received(user_id, username, text)

    # --- Auth check ---
    authorized, reason = user_mgr.is_authorized(user_id)
    if not authorized:
        audit.log_unauthorized(user_id, username, reason)
        await update.message.reply_text(reason)
        return

    # --- Rate limit ---
    within_limit, limit_reason = user_mgr.check_rate_limit(user_id)
    if not within_limit:
        audit.log_rate_limited(user_id, limit_reason)
        await update.message.reply_text(limit_reason)
        return

    # --- Input filter ---
    input_scan = scan_input(text, ALLOWED_DIRS)

    if input_scan.blocked:
        user_mgr.record_threat(user_id, CONFIG["threat"]["block_penalty"])
        audit.log_input_blocked(user_id, username, text, input_scan.findings, input_scan.score)

        # Check if this pushed them over auto-block threshold
        if user_mgr.get_threat_score(user_id) >= CONFIG["threat"]["auto_block_score"]:
            audit.log_auto_blocked(user_id, user_mgr.get_threat_score(user_id))

        await update.message.reply_text(
            "Your message was blocked by the security filter.\n"
            f"Findings: {len(input_scan.findings)} issue(s) detected."
        )
        return

    if input_scan.findings:
        # Suspicious but not blocked - log it
        audit.log_input_suspicious(user_id, username, text, input_scan.findings, input_scan.score)

    # --- LLM call ---
    try:
        llm_response = await llm.generate(text)
    except Exception as e:
        audit.log_error(user_id, str(e))
        await update.message.reply_text("Sorry, I couldn't reach the LLM. Try again later.")
        return

    # --- Output filter ---
    output_scan = scan_output(llm_response, CANARY, ALLOWED_DIRS)

    if output_scan.blocked:
        audit.log_output_blocked(user_id, output_scan.findings)
        await update.message.reply_text(
            "The response was blocked by the security filter (potential data leak)."
        )
        return

    if output_scan.findings:
        audit.log_output_redacted(user_id, output_scan.findings)

    # --- Send response ---
    response_text = output_scan.redacted_text or llm_response
    # Telegram message limit is 4096 chars
    if len(response_text) > 4000:
        response_text = response_text[:4000] + "\n\n[truncated]"

    audit.log_response_sent(user_id, len(response_text))
    await update.message.reply_text(response_text)


def main():
    token = CONFIG["telegram"]["bot_token"]
    if token == "YOUR_TELEGRAM_BOT_TOKEN":
        print("ERROR: Set your Telegram bot token in config.yaml")
        return

    app = ApplicationBuilder().token(token).build()

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))

    print("Bot starting...")
    app.run_polling()


if __name__ == "__main__":
    main()
