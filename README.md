# Prompt Guard

Prompt injection detection for LLM apps. Zero dependencies. Runs offline.

## Install

```bash
git clone <repo-url> && cd prompt_guard
pip install .                # core library only
pip install ".[telegram]"    # + telegram bot dependencies
```

## Library Usage

```python
from prompt_guard import scan_input, scan_output

# Before sending user text to your LLM
result = scan_input(text, allowed_dirs=["/safe/dir"])
result.blocked   # True if injection detected
result.findings  # List of what triggered
result.score     # Threat score

# Before returning LLM response to user
output = scan_output(response, canary="MY_CANARY", allowed_dirs=["/safe/dir"])
output.blocked       # True if system prompt leaked (canary detected)
output.redacted_text # Response with secrets and unauthorized paths removed
output.findings      # What was redacted
```

Works as middleware in any Python app — Flask, FastAPI, Discord bot, CLI tool, RAG pipeline.

## Telegram Bot

Full working bot in `examples/` that connects to a local Ollama instance:

```bash
# Edit examples/config.yaml (bot token, model, allowed dirs, rate limits)
ollama serve
python examples/bot.py
```

Bot commands: `/start`, `/status` (shows rate limit stats and threat score).

## What It Catches

**Inputs** — instruction overrides, role switching, jailbreaks, prompt extraction, delimiter injection (`[SYSTEM]`, `<|im_start|>`), path traversal, command injection, encoding tricks (zero-width chars, homoglyphs, base64), structural attacks (fake conversation turns, HTML comments).

**Outputs** — API keys (OpenAI, Anthropic, AWS, GCP, Stripe, GitHub, GitLab, Slack, Telegram, SendGrid, and more), private keys, JWTs, database connection strings, passwords, paths outside allowed directories, system prompt canary leaks.

## Extras

- `UserManager` — per-user allowlist/blocklist, rate limiting, threat score that accumulates on blocked messages and decays over time, auto-blocks at threshold
- `AuditLogger` — every event logged as JSON lines (`audit.log`), queryable with `jq`

## Limitations

Pattern-based. Won't catch novel techniques, split attacks across messages, or subtle social engineering. Best used alongside sandboxing (Docker/chroot) your LLM process.
