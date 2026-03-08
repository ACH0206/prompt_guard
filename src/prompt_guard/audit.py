"""
Audit logging - records all bot interactions, blocked attempts, and threat events.
Every message in and out is logged with full context for forensic review.
"""

import json
import logging
import time
from pathlib import Path


class AuditLogger:
    def __init__(self, audit_file: str = "audit.log", log_level: str = "INFO"):
        self.audit_file = Path(audit_file)

        # Structured audit log (JSON lines)
        self.logger = logging.getLogger("prompt_guard.audit")
        self.logger.setLevel(getattr(logging, log_level.upper(), logging.INFO))

        # File handler for persistent audit trail
        fh = logging.FileHandler(self.audit_file, encoding="utf-8")
        fh.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(fh)

        # Console handler for real-time monitoring
        ch = logging.StreamHandler()
        ch.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(ch)

    def _log(self, event: dict):
        event["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        event["epoch"] = time.time()
        self.logger.info(json.dumps(event, ensure_ascii=False))

    def log_message_received(self, user_id: int, username: str | None, text: str):
        self._log({
            "event": "message_received",
            "user_id": user_id,
            "username": username,
            "text_length": len(text),
            "text_preview": text[:200],
        })

    def log_input_blocked(
        self, user_id: int, username: str | None, text: str,
        findings: list[str], score: float,
    ):
        self._log({
            "event": "input_blocked",
            "user_id": user_id,
            "username": username,
            "text_length": len(text),
            "text_preview": text[:500],
            "findings": findings,
            "threat_score": round(score, 2),
        })

    def log_input_suspicious(
        self, user_id: int, username: str | None, text: str,
        findings: list[str], score: float,
    ):
        """Log messages that scored > 0 but below blocking threshold."""
        self._log({
            "event": "input_suspicious",
            "user_id": user_id,
            "username": username,
            "text_length": len(text),
            "text_preview": text[:500],
            "findings": findings,
            "threat_score": round(score, 2),
        })

    def log_output_blocked(self, user_id: int, findings: list[str]):
        self._log({
            "event": "output_blocked",
            "user_id": user_id,
            "findings": findings,
        })

    def log_output_redacted(self, user_id: int, findings: list[str]):
        self._log({
            "event": "output_redacted",
            "user_id": user_id,
            "findings": findings,
        })

    def log_response_sent(self, user_id: int, response_length: int):
        self._log({
            "event": "response_sent",
            "user_id": user_id,
            "response_length": response_length,
        })

    def log_rate_limited(self, user_id: int, reason: str):
        self._log({
            "event": "rate_limited",
            "user_id": user_id,
            "reason": reason,
        })

    def log_unauthorized(self, user_id: int, username: str | None, reason: str):
        self._log({
            "event": "unauthorized",
            "user_id": user_id,
            "username": username,
            "reason": reason,
        })

    def log_auto_blocked(self, user_id: int, threat_score: float):
        self._log({
            "event": "auto_blocked",
            "user_id": user_id,
            "threat_score": round(threat_score, 2),
        })

    def log_error(self, user_id: int, error: str):
        self._log({
            "event": "error",
            "user_id": user_id,
            "error": error,
        })
