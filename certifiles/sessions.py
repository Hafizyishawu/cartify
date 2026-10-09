"""Sessions and CSRF tokens.

Two decisions here are worth stating rather than inferring from the code.

**Session tokens are stored hashed.** The database holds a SHA-256 of the token,
never the token itself, so a leaked database yields no usable sessions. The same
reasoning as password hashing, applied to the credential that is actually
presented on every request.

**Sessions rotate when authority changes.** Signing in and completing a second
factor both issue a new token and destroy the old one. Without that, a token
captured before the second factor keeps whatever authority the session later
gains, which is session fixation.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path

TOKEN_BYTES = 32
# Long enough to be usable, short enough that a stolen token expires on its own.
SESSION_TTL_SECONDS = 12 * 3600
# A session that has authenticated but not yet passed its second factor can do
# almost nothing, so it gets a much shorter life.
PARTIAL_TTL_SECONDS = 10 * 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    token_hash  BLOB PRIMARY KEY,
    identity_id TEXT NOT NULL,
    csrf_secret BLOB NOT NULL,
    mfa_passed  INTEGER NOT NULL DEFAULT 0,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_by_account ON sessions (identity_id);
"""


class SessionError(RuntimeError):
    """The session store refused an operation."""


@dataclass(frozen=True, slots=True)
class Session:
    identity_id: str
    mfa_passed: bool
    created_at: int
    expires_at: int
    csrf_token: str


def _hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class SessionStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "SessionStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def create(
        self, identity_id: str, mfa_passed: bool = False, now: int | None = None
    ) -> str:
        """Issue a session and return its token. The token is never stored."""
        now = int(time.time()) if now is None else now
        token = secrets.token_urlsafe(TOKEN_BYTES)
        ttl = SESSION_TTL_SECONDS if mfa_passed else PARTIAL_TTL_SECONDS
        self._connection.execute(
            "INSERT INTO sessions (token_hash, identity_id, csrf_secret, mfa_passed,"
            " created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (_hash_token(token), identity_id, secrets.token_bytes(32),
             1 if mfa_passed else 0, now, now + ttl),
        )
        return token

    def resolve(self, token: str | None, now: int | None = None) -> Session | None:
        """Look up a session. Returns None for anything not currently valid."""
        if not isinstance(token, str) or not token:
            return None
        now = int(time.time()) if now is None else now
        row = self._connection.execute(
            "SELECT identity_id, csrf_secret, mfa_passed, created_at, expires_at"
            " FROM sessions WHERE token_hash = ?",
            (_hash_token(token),),
        ).fetchone()
        if row is None:
            return None
        identity_id, csrf_secret, mfa_passed, created_at, expires_at = row
        if now >= expires_at:
            self.revoke(token)
            return None
        return Session(
            identity_id=identity_id,
            mfa_passed=bool(mfa_passed),
            created_at=created_at,
            expires_at=expires_at,
            csrf_token=hmac.new(csrf_secret, b"csrf", hashlib.sha256).hexdigest(),
        )

    def upgrade(self, token: str, now: int | None = None) -> str:
        """Mark a session as having passed its second factor, with a new token.

        Rotating rather than updating in place is the point: a token captured
        before the second factor must not inherit the authority granted after
        it.
        """
        session = self.resolve(token, now=now)
        if session is None:
            raise SessionError("no such session")
        self.revoke(token)
        return self.create(session.identity_id, mfa_passed=True, now=now)

    def revoke(self, token: str) -> None:
        self._connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?", (_hash_token(token),)
        )

    def revoke_all(self, identity_id: str) -> int:
        cursor = self._connection.execute(
            "DELETE FROM sessions WHERE identity_id = ?", (identity_id,)
        )
        return cursor.rowcount

    def purge_expired(self, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        cursor = self._connection.execute(
            "DELETE FROM sessions WHERE expires_at <= ?", (now,)
        )
        return cursor.rowcount

    def check_csrf(self, session: Session | None, presented: str | None) -> bool:
        """Compare a submitted CSRF token in constant time."""
        if session is None or not isinstance(presented, str):
            return False
        return hmac.compare_digest(session.csrf_token, presented)
