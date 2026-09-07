"""Rate limiting for the paths an attacker gets unlimited attempts at.

Three flows need this and each for a different reason. Sign-in, because a
password is only as strong as the number of guesses allowed against it. Account
creation, because unlimited accounts means unlimited registrations. And
registration itself, because the threat model's mass pre-emptive registration
attack is precisely an attacker submitting claims faster than a person could
create work.

A sliding window rather than a fixed one. Fixed windows let an attacker spend
the whole budget at the end of one window and the whole budget at the start of
the next, which is twice the intended rate at the moment it matters most.
"""

from __future__ import annotations

import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS attempts (
    bucket TEXT NOT NULL,
    key    TEXT NOT NULL,
    at     INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS attempts_by_key ON attempts (bucket, key, at);
"""


class RateLimitError(RuntimeError):
    """The limiter refused a configuration, not a request."""


@dataclass(frozen=True, slots=True)
class Limit:
    name: str
    allowed: int
    window_seconds: int

    def __post_init__(self) -> None:
        if self.allowed < 1 or self.window_seconds < 1:
            raise RateLimitError("a limit needs a positive allowance and window")


@dataclass(frozen=True, slots=True)
class Decision:
    allowed: bool
    remaining: int
    retry_after: int


# Deliberately strict on the two flows where being wrong is expensive, and
# looser on registration, where a legitimate artist may publish a batch.
SIGN_IN = Limit("sign-in", allowed=5, window_seconds=15 * 60)
ACCOUNT_CREATION = Limit("account-creation", allowed=3, window_seconds=60 * 60)
WORK_REGISTRATION = Limit("work-registration", allowed=60, window_seconds=60 * 60)
MFA_ATTEMPT = Limit("mfa", allowed=8, window_seconds=15 * 60)


class RateLimiter:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "RateLimiter":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def check(self, limit: Limit, key: str, now: int | None = None) -> Decision:
        """Report whether an attempt is allowed, without recording one."""
        now = int(time.time()) if now is None else now
        cutoff = now - limit.window_seconds
        row = self._connection.execute(
            "SELECT COUNT(*), COALESCE(MIN(at), 0) FROM attempts"
            " WHERE bucket = ? AND key = ? AND at > ?",
            (limit.name, key, cutoff),
        ).fetchone()
        used, oldest = row
        remaining = max(0, limit.allowed - used)
        retry_after = 0 if remaining else max(1, oldest + limit.window_seconds - now)
        return Decision(remaining > 0, remaining, retry_after)

    def record(self, limit: Limit, key: str, now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        self._connection.execute(
            "INSERT INTO attempts (bucket, key, at) VALUES (?, ?, ?)",
            (limit.name, key, now),
        )

    def consume(self, limit: Limit, key: str, now: int | None = None) -> Decision:
        """Check and record in one step.

        Records the attempt even when it is refused. An attacker who keeps
        trying should keep the window open, not reset it by being blocked.
        """
        decision = self.check(limit, key, now=now)
        self.record(limit, key, now=now)
        return decision

    def clear(self, limit: Limit, key: str) -> None:
        """Forget a key's attempts. For a successful sign-in, not for a failure."""
        self._connection.execute(
            "DELETE FROM attempts WHERE bucket = ? AND key = ?", (limit.name, key)
        )

    def purge(self, before: int | None = None) -> int:
        before = int(time.time()) - 86_400 if before is None else before
        cursor = self._connection.execute("DELETE FROM attempts WHERE at < ?", (before,))
        return cursor.rowcount
