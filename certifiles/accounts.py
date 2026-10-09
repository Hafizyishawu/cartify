"""Accounts, passwords and second factors.

The account exists to answer one question: who is asserting this claim? A record
carries an assurance level, and that level is exactly the strength of the
identity behind it, so everything here is load bearing for the log's meaning
rather than merely for access control.

Two separations are structural and neither can be relaxed later.

**The log never learns who you are.** An account holds an email address; the log
holds an opaque identifier with no derivable relationship to it. Not a hash of
the email, which would be enumerable, but a random token. An append-only log
cannot honour an erasure request, so anything erasable must never enter it.

**Verification never requires an account.** Nothing here gates reading. Accounts
gate claiming, because a claim needs someone behind it.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import secrets
import sqlite3
import struct
import time
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from certifiles.record import AssuranceLevel

# scrypt parameters. n=2**15 costs roughly 60-100ms per hash on commodity
# hardware, which is the point: it is the attacker's cost per guess on a stolen
# database, and the honest tradeoff is that a login is measurably slower.
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
SALT_BYTES = 16
# scrypt needs 128 * n * r bytes, which at these parameters is 32MB. OpenSSL
# refuses that under its own default ceiling, so the ceiling is raised here
# rather than the cost being quietly lowered to fit under it.
SCRYPT_MAXMEM = 128 * SCRYPT_N * SCRYPT_R * 2

# A random identifier, not derived from the email. A hash of the address would
# let anyone holding the published log test whether a given person registered
# anything, which is exactly the deanonymisation the opaque id prevents.
IDENTITY_BYTES = 12

TOTP_DIGITS = 6
TOTP_PERIOD = 30
# One step either side, so a slow submission or a slightly wrong clock still
# works. Wider than that and a stolen code stays useful for too long.
TOTP_DRIFT_STEPS = 1

EMAIL_PATTERN = re.compile(r"\A[^@\s]+@[^@\s]+\.[^@\s]+\Z")
MIN_PASSWORD_LENGTH = 12


class AccountError(ValueError):
    """The account store refused an operation."""


class MfaState(StrEnum):
    NONE = "none"
    PENDING = "pending"
    ACTIVE = "active"


@dataclass(frozen=True, slots=True)
class Account:
    identity_id: str
    email: str
    assurance_level: AssuranceLevel
    mfa_state: MfaState
    created_at: int

    @property
    def may_register_works(self) -> bool:
        """Whether this account may write to the log.

        The threat model requires MFA on any account holding records. Enforcing
        it at the point of writing rather than at sign-in means an account
        cannot accumulate records while its second factor is merely pending.
        """
        return self.mfa_state is MfaState.ACTIVE


SCHEMA = """
CREATE TABLE IF NOT EXISTS accounts (
    identity_id   TEXT PRIMARY KEY,
    email         TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    password_salt BLOB NOT NULL,
    totp_secret   BLOB,
    mfa_state     TEXT NOT NULL DEFAULT 'none',
    last_totp_step INTEGER,
    assurance     TEXT NOT NULL,
    created_at    INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS account_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    identity_id TEXT NOT NULL,
    event      TEXT NOT NULL,
    at         INTEGER NOT NULL,
    detail     TEXT
);

CREATE INDEX IF NOT EXISTS events_by_account ON account_events (identity_id, at);

-- The audit trail is append-only. Account recovery is the softest path to
-- everything an account owns, so the record of it must not be editable by the
-- code that performs it.
CREATE TRIGGER IF NOT EXISTS account_events_no_update
BEFORE UPDATE ON account_events
BEGIN SELECT RAISE(ABORT, 'account events are append-only'); END;

CREATE TRIGGER IF NOT EXISTS account_events_no_delete
BEFORE DELETE ON account_events
BEGIN SELECT RAISE(ABORT, 'account events are append-only'); END;
"""


def hash_password(password: str, salt: bytes | None = None) -> tuple[bytes, bytes]:
    if not isinstance(password, str):
        raise AccountError("password must be a string")
    if len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(
            f"password must be at least {MIN_PASSWORD_LENGTH} characters"
        )
    salt = salt or secrets.token_bytes(SALT_BYTES)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt,
        n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_DKLEN,
        maxmem=SCRYPT_MAXMEM,
    )
    return digest, salt


def totp_secret() -> bytes:
    return secrets.token_bytes(20)


def totp_code(secret: bytes, step: int) -> str:
    """RFC 6238 code for a counter step."""
    mac = hmac.new(secret, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(truncated % (10**TOTP_DIGITS)).zfill(TOTP_DIGITS)


def totp_uri(email: str, secret: bytes, issuer: str = "Certifiles") -> str:
    encoded = base64.b32encode(secret).decode("ascii").rstrip("=")
    return (
        f"otpauth://totp/{issuer}:{email}?secret={encoded}"
        f"&issuer={issuer}&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


class AccountStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "AccountStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---- writing -------------------------------------------------------

    def create(self, email: str, password: str, now: int | None = None) -> Account:
        email = self._normalise_email(email)
        digest, salt = hash_password(password)
        identity_id = secrets.token_urlsafe(IDENTITY_BYTES)
        created = int(time.time()) if now is None else now

        try:
            self._connection.execute(
                "INSERT INTO accounts (identity_id, email, password_hash,"
                " password_salt, mfa_state, assurance, created_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?)",
                (identity_id, email, digest, salt, str(MfaState.NONE),
                 str(AssuranceLevel.UNVERIFIED), created),
            )
        except sqlite3.IntegrityError as exc:
            raise AccountError("an account already exists for that address") from exc

        self._log(identity_id, "account.created", created)
        return self.by_identity(identity_id)

    def authenticate(self, email: str, password: str) -> Account | None:
        """Check a password. Returns None for both wrong password and no account.

        The work is done even when no account exists, so the response time does
        not reveal which addresses are registered.
        """
        row = self._connection.execute(
            "SELECT identity_id, password_hash, password_salt FROM accounts"
            " WHERE email = ?",
            (self._normalise_email(email, validate=False),),
        ).fetchone()

        if row is None:
            hash_password(password if len(password) >= MIN_PASSWORD_LENGTH
                          else "x" * MIN_PASSWORD_LENGTH,
                          salt=b"\x00" * SALT_BYTES)
            return None

        identity_id, stored, salt = row
        try:
            candidate, _ = hash_password(password, salt=salt)
        except AccountError:
            return None
        if not hmac.compare_digest(candidate, stored):
            self._log(identity_id, "auth.failed", int(time.time()))
            return None
        return self.by_identity(identity_id)

    def begin_mfa_enrolment(self, identity_id: str) -> bytes:
        secret = totp_secret()
        self._connection.execute(
            "UPDATE accounts SET totp_secret = ?, mfa_state = ? WHERE identity_id = ?",
            (secret, str(MfaState.PENDING), identity_id),
        )
        self._log(identity_id, "mfa.enrolment_started", int(time.time()))
        return secret

    def confirm_mfa(self, identity_id: str, code: str, now: int | None = None) -> bool:
        """Activate the second factor once the user proves they hold it."""
        if not self.verify_totp(identity_id, code, now=now, allow_pending=True):
            return False
        self._connection.execute(
            "UPDATE accounts SET mfa_state = ? WHERE identity_id = ?",
            (str(MfaState.ACTIVE), identity_id),
        )
        self._log(identity_id, "mfa.activated", int(time.time()))
        return True

    def verify_totp(
        self, identity_id: str, code: str, now: int | None = None,
        allow_pending: bool = False,
    ) -> bool:
        row = self._connection.execute(
            "SELECT totp_secret, mfa_state, last_totp_step FROM accounts"
            " WHERE identity_id = ?",
            (identity_id,),
        ).fetchone()
        if row is None:
            return False
        secret, state, last_step = row
        if secret is None:
            return False
        if state == str(MfaState.PENDING) and not allow_pending:
            return False
        if not isinstance(code, str) or not code.isdigit():
            return False

        current = int((time.time() if now is None else now) // TOTP_PERIOD)
        for step in range(current - TOTP_DRIFT_STEPS, current + TOTP_DRIFT_STEPS + 1):
            if not hmac.compare_digest(totp_code(secret, step), code):
                continue
            # A code is single use. Without this a code observed in transit, or
            # over someone's shoulder, stays valid for the rest of its window.
            if last_step is not None and step <= last_step:
                self._log(identity_id, "mfa.replay_rejected", int(time.time()))
                return False
            self._connection.execute(
                "UPDATE accounts SET last_totp_step = ? WHERE identity_id = ?",
                (step, identity_id),
            )
            return True
        return False

    def set_password(self, identity_id: str, password: str) -> None:
        """Replace a password. Callers must revoke sessions separately."""
        digest, salt = hash_password(password)
        self._connection.execute(
            "UPDATE accounts SET password_hash = ?, password_salt = ? WHERE identity_id = ?",
            (digest, salt, identity_id),
        )
        self._log(identity_id, "password.changed", int(time.time()))

    def by_email(self, email: str) -> Account | None:
        row = self._connection.execute(
            "SELECT identity_id FROM accounts WHERE email = ?",
            (self._normalise_email(email, validate=False),),
        ).fetchone()
        return self.by_identity(row[0]) if row else None

    def mark_email_verified(self, identity_id: str) -> Account | None:
        """Raise assurance to email-verified, but never lower it.

        An account that has since proven domain control must not be demoted by
        confirming an address, and no change here reaches records already in
        the log.
        """
        account = self.by_identity(identity_id)
        if account is None:
            return None
        if account.assurance_level is AssuranceLevel.UNVERIFIED:
            self.set_assurance(identity_id, AssuranceLevel.EMAIL)
        self._log(identity_id, "email.verified", int(time.time()))
        return self.by_identity(identity_id)

    def clear_mfa(self, identity_id: str) -> None:
        """Remove a second factor after recovery, forcing fresh enrolment.

        The old secret is gone rather than reused: recovery is used precisely
        when the authenticator is lost, so keeping the secret would leave an
        account depending on something its owner cannot reach.
        """
        self._connection.execute(
            "UPDATE accounts SET totp_secret = NULL, mfa_state = ?,"
            " last_totp_step = NULL WHERE identity_id = ?",
            (str(MfaState.NONE), identity_id),
        )
        self._log(identity_id, "mfa.reset_by_recovery", int(time.time()))

    def set_assurance(self, identity_id: str, level: AssuranceLevel) -> None:
        """Raise or lower the identity strength recorded on future records.

        Records already in the log keep the assurance they were issued under.
        Nothing here reaches back into the log, and nothing could.
        """
        self._connection.execute(
            "UPDATE accounts SET assurance = ? WHERE identity_id = ?",
            (str(level), identity_id),
        )
        self._log(identity_id, "assurance.changed", int(time.time()), str(level))

    # ---- reading -------------------------------------------------------

    def by_identity(self, identity_id: str) -> Account | None:
        row = self._connection.execute(
            "SELECT identity_id, email, assurance, mfa_state, created_at"
            " FROM accounts WHERE identity_id = ?",
            (identity_id,),
        ).fetchone()
        if row is None:
            return None
        return Account(
            identity_id=row[0], email=row[1],
            assurance_level=AssuranceLevel(row[2]),
            mfa_state=MfaState(row[3]), created_at=row[4],
        )

    def events(self, identity_id: str) -> list[tuple[str, int, str | None]]:
        return [
            (event, at, detail)
            for event, at, detail in self._connection.execute(
                "SELECT event, at, detail FROM account_events WHERE identity_id = ?"
                " ORDER BY at, id",
                (identity_id,),
            )
        ]

    # ---- internals -----------------------------------------------------

    def _log(self, identity_id: str, event: str, at: int, detail: str | None = None) -> None:
        self._connection.execute(
            "INSERT INTO account_events (identity_id, event, at, detail)"
            " VALUES (?, ?, ?, ?)",
            (identity_id, event, at, detail),
        )

    @staticmethod
    def _normalise_email(email: str, validate: bool = True) -> str:
        if not isinstance(email, str):
            raise AccountError("email must be a string")
        cleaned = email.strip().lower()
        if validate and not EMAIL_PATTERN.match(cleaned):
            raise AccountError("that does not look like an email address")
        return cleaned
