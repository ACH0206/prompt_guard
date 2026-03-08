"""
Per-user rate limiting, allowlist/blocklist, and threat scoring.
"""

import time
from dataclasses import dataclass, field


@dataclass
class UserState:
    message_timestamps: list[float] = field(default_factory=list)
    threat_score: float = 0.0
    last_decay: float = field(default_factory=time.time)
    total_blocked: int = 0


class UserManager:
    def __init__(
        self,
        allowed_users: list[int] | None = None,
        blocked_users: list[int] | None = None,
        max_per_minute: int = 10,
        max_per_hour: int = 60,
        auto_block_score: float = 10.0,
        block_penalty: float = 2.0,
        decay_per_hour: float = 1.0,
    ):
        self.allowed_users = set(allowed_users) if allowed_users else None
        self.blocked_users = set(blocked_users) if blocked_users else set()
        self.max_per_minute = max_per_minute
        self.max_per_hour = max_per_hour
        self.auto_block_score = auto_block_score
        self.block_penalty = block_penalty
        self.decay_per_hour = decay_per_hour
        self.users: dict[int, UserState] = {}

    def _get_state(self, user_id: int) -> UserState:
        if user_id not in self.users:
            self.users[user_id] = UserState()
        return self.users[user_id]

    def is_authorized(self, user_id: int) -> tuple[bool, str]:
        """Check if user is allowed to use the bot."""
        if user_id in self.blocked_users:
            return False, "You are blocked from using this bot."

        if self.allowed_users is not None and user_id not in self.allowed_users:
            return False, "You are not authorized to use this bot."

        state = self._get_state(user_id)

        # Apply threat score decay
        now = time.time()
        hours_elapsed = (now - state.last_decay) / 3600
        if hours_elapsed >= 1:
            decay = hours_elapsed * self.decay_per_hour
            state.threat_score = max(0, state.threat_score - decay)
            state.last_decay = now

        # Check if auto-blocked by threat score
        if state.threat_score >= self.auto_block_score:
            return False, "Temporarily blocked due to repeated suspicious activity."

        return True, ""

    def check_rate_limit(self, user_id: int) -> tuple[bool, str]:
        """Check if user is within rate limits."""
        state = self._get_state(user_id)
        now = time.time()

        # Clean old timestamps
        state.message_timestamps = [
            t for t in state.message_timestamps if now - t < 3600
        ]

        # Check per-minute
        recent_minute = sum(1 for t in state.message_timestamps if now - t < 60)
        if recent_minute >= self.max_per_minute:
            return False, f"Rate limit: max {self.max_per_minute} messages per minute."

        # Check per-hour
        if len(state.message_timestamps) >= self.max_per_hour:
            return False, f"Rate limit: max {self.max_per_hour} messages per hour."

        state.message_timestamps.append(now)
        return True, ""

    def record_threat(self, user_id: int, score: float):
        """Add threat score for a suspicious message."""
        state = self._get_state(user_id)
        state.threat_score += score
        state.total_blocked += 1

    def get_threat_score(self, user_id: int) -> float:
        state = self._get_state(user_id)
        return state.threat_score

    def get_stats(self, user_id: int) -> dict:
        """Get user stats for admin inspection."""
        state = self._get_state(user_id)
        return {
            "threat_score": round(state.threat_score, 2),
            "total_blocked": state.total_blocked,
            "messages_last_hour": len(state.message_timestamps),
        }
