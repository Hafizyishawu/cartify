"""Single-use, expiring tokens for email verification and account recovery.

These are bearer credentials sent over email, which is not a confidential
channel. Everything here follows from that.

**Stored hashed.** The database holds SHA-256 of the token, never the token, so
a leaked database yields nothing usable. Same reasoning as sessions and
passwords, applied to the credential that arrives in an inbox.

**Single use, and consumed atomically.** A token is deleted in the same
statement that claims it, so two simultaneous redemptions cannot both succeed.

**Short lived, and shorter the more they grant.** A verification link proves
someone reads the inbox. A reset link changes a password. They are not the same
risk and do not get the same lifetime.

Recovery codes are here too because they are the same shape: a bearer secret
that must survive exactly one use. They exist for the case that otherwise ends
an account permanently, losing the second factor, and they are the reason a
password reset does not need to bypass MFA.
"""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

TOKEN_BYTES = 32
RECOVERY_CODE_COUNT = 10
RECOVERY_CODE_BYTES = 5


class TokenPurpose(StrEnum):
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET = "password_reset"
    RECOVERY_CODE = "recovery_code"


# A verification link only proves someone reads the inbox, so it can live a
# day. A reset link changes a password, so it lives long enough to walk to a
# different device and no longer. Recovery codes never expire: the situation
# they exist for is discovering, months later, that a phone is gone.
LIFETIMES = {
    TokenPurpose.EMAIL_VERIFICATION: 24 * 3600,
    TokenPurpose.PASSWORD_RESET: 30 * 60,
    TokenPurpose.RECOVERY_CODE: None,
}


class TokenError(RuntimeError):
    """The token store refused an operation."""


@dataclass(frozen=True, slots=True)
class IssuedToken:
    identity_id: str
    purpose: TokenPurpose
    secret: str
    expires_at: int | None


SCHEMA = """
CREATE TABLE IF NOT EXISTS tokens (
    token_hash  BLOB PRIMARY KEY,
    identity_id TEXT NOT NULL,
    purpose     TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER
);

CREATE INDEX IF NOT EXISTS tokens_by_account ON tokens (identity_id, purpose);
"""


def _hash(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def _format_recovery_code(raw: bytes) -> str:
    body = raw.hex()
    return f"{body[:5]}-{body[5:10]}"


class TokenStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "TokenStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def issue(
        self, identity_id: str, purpose: TokenPurpose, now: int | None = None
    ) -> IssuedToken:
        """Mint a token, invalidating any earlier one for the same purpose.

        Superseding matters: two live reset links means two chances for a stale
        one to be found in an old inbox.
        """
        now = int(time.time()) if now is None else now
        if purpose is TokenPurpose.RECOVERY_CODE:
            raise TokenError("recovery codes are issued as a set, use issue_recovery_codes")
        self.revoke_all(identity_id, purpose)

        secret = secrets.token_urlsafe(TOKEN_BYTES)
        lifetime = LIFETIMES[purpose]
        expires_at = None if lifetime is None else now + lifetime
        self._connection.execute(
            "INSERT INTO tokens (token_hash, identity_id, purpose, created_at,"
            " expires_at) VALUES (?, ?, ?, ?, ?)",
            (_hash(secret), identity_id, str(purpose), now, expires_at),
        )
        return IssuedToken(identity_id, purpose, secret, expires_at)

    def issue_recovery_codes(
        self, identity_id: str, now: int | None = None
    ) -> list[str]:
        """Replace this account's recovery codes and return the new set.

        Shown once. They are stored hashed, so nothing can display them again,
        which is the property that makes them safe to store at all.
        """
        now = int(time.time()) if now is None else now
        self.revoke_all(identity_id, TokenPurpose.RECOVERY_CODE)
        codes = [
            _format_recovery_code(secrets.token_bytes(RECOVERY_CODE_BYTES))
            for _ in range(RECOVERY_CODE_COUNT)
        ]
        self._connection.executemany(
            "INSERT INTO tokens (token_hash, identity_id, purpose, created_at,"
            " expires_at) VALUES (?, ?, ?, ?, NULL)",
            [(_hash(c), identity_id, str(TokenPurpose.RECOVERY_CODE), now) for c in codes],
        )
        return codes

    def redeem(
        self, secret: str, purpose: TokenPurpose, now: int | None = None
    ) -> str | None:
        """Consume a token and return whose it was, or None.

        The delete is the claim. Doing it in one statement means two
        simultaneous redemptions cannot both succeed, which a read-then-delete
        would allow.
        """
        if not isinstance(secret, str) or not secret:
            return None
        now = int(time.time()) if now is None else now
        row = self._connection.execute(
            "DELETE FROM tokens WHERE token_hash = ? AND purpose = ?"
            " AND (expires_at IS NULL OR expires_at > ?)"
            " RETURNING identity_id",
            (_hash(secret.strip()), str(purpose), now),
        ).fetchone()
        return row[0] if row else None

    def remaining(self, identity_id: str, purpose: TokenPurpose) -> int:
        return self._connection.execute(
            "SELECT COUNT(*) FROM tokens WHERE identity_id = ? AND purpose = ?",
            (identity_id, str(purpose)),
        ).fetchone()[0]

    def revoke_all(self, identity_id: str, purpose: TokenPurpose) -> int:
        cursor = self._connection.execute(
            "DELETE FROM tokens WHERE identity_id = ? AND purpose = ?",
            (identity_id, str(purpose)),
        )
        return cursor.rowcount

    def purge_expired(self, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        cursor = self._connection.execute(
            "DELETE FROM tokens WHERE expires_at IS NOT NULL AND expires_at <= ?", (now,)
        )
        return cursor.rowcount
