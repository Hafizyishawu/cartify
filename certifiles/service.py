"""The HTTP service: accounts, sessions, and the one write path into the log.

Deliberately thin. Every decision that matters lives in accounts.py,
sessions.py, ratelimit.py and log.py, all of which are testable with no server
running. This file routes requests to them and applies the transport-level
protections a browser needs.

**A production deployment replaces this transport.** `http.server` is a
development server: single-threaded, no TLS, no hardening. The domain logic
underneath is what would be carried across, which is why the boundary is here
rather than woven through.

Two properties the routing enforces, both from the threat model:

- **Nothing on the read path requires a session.** Verification stays public and
  anonymous, and there is no route that would let that change quietly.
- **Writing to the log requires an active second factor**, checked at the write
  rather than at sign-in, so an account cannot accumulate records while its
  factor is merely pending.
"""

from __future__ import annotations

import json
import mimetypes
import secrets
import time
from dataclasses import dataclass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from certifiles.accounts import (
    MIN_PASSWORD_LENGTH,
    AccountError,
    AccountStore,
    MfaState,
    totp_uri,
)
from certifiles.domains import DomainError, challenge_for, normalise_domain, verify as verify_domain
from certifiles.mail import (
    no_account_message,
    password_reset_message,
    recovery_used_message,
    verification_message,
)
from certifiles.record import AssuranceLevel
from certifiles.tokens import TokenPurpose, TokenStore
from certifiles.fingerprint import Fingerprint, FingerprintError, FingerprintKind
from certifiles.log import TransparencyLog
from certifiles.ratelimit import (
    ACCOUNT_CREATION,
    DOMAIN_CHECK,
    MFA_ATTEMPT,
    SIGN_IN,
    WORK_REGISTRATION,
    RateLimiter,
)
from certifiles.record import (
    ClaimType,
    Content,
    Issuer,
    Record,
    RecordError,
)

SESSION_COOKIE = "certifiles_session"
MAX_BODY_BYTES = 64 * 1024

# script-src 'self' rather than a nonce: the public pages are static by design
# and have to work behind any file host, with no server able to stamp a nonce
# into them. That means no inline script anywhere, which is a real constraint
# on the pages rather than a header that merely looks strict.
#
# style-src allows inline because the pages set a handful of element styles;
# an injected style cannot execute, and tightening it would cost more than it
# buys until those move into classes.
CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
])

SECURITY_HEADERS = {
    "Content-Security-Policy": CONTENT_SECURITY_POLICY,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "geolocation=(), camera=(), microphone=()",
}


@dataclass
class Services:
    accounts: AccountStore
    sessions: object
    limiter: RateLimiter
    log: TransparencyLog
    web_root: Path
    tokens: TokenStore = None
    mailer: object = None
    resolver: object = None
    domain_secret: bytes = b""
    base_url: str = "http://127.0.0.1:8770"
    origin: str = "certifiles.example/log"
    secure_cookies: bool = True


class ApiError(Exception):
    def __init__(self, status: int, message: str, retry_after: int | None = None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


def _client_key(handler: BaseHTTPRequestHandler) -> str:
    """The key a rate limit is counted against.

    The peer address, not a header. X-Forwarded-For is attacker controlled
    unless a trusted proxy sets it, and treating it as identity would let one
    client spread its attempts across an unlimited number of buckets.
    """
    return handler.client_address[0]


class Handler(BaseHTTPRequestHandler):
    services: Services = None  # injected by serve()
    server_version = "certifiles"
    sys_version = ""

    # ---- plumbing ------------------------------------------------------

    def log_message(self, fmt, *args):  # quieter, and never logs a query string
        pass

    def _session(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie[SESSION_COOKIE].value if SESSION_COOKIE in cookie else None
        return token, self.services.sessions.resolve(token)

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY_BYTES:
            raise ApiError(413, "That request is too large.")
        try:
            return json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, UnicodeDecodeError):
            raise ApiError(400, "That request body is not valid JSON.")

    def _send_json(self, status: int, payload: dict, set_cookie: str | None = None,
                   clear_cookie: bool = False, retry_after: int | None = None) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        # A browser must never be talked into treating a JSON response as
        # something executable, and no page here is meant to be framed.
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        if set_cookie:
            attrs = f"{SESSION_COOKIE}={set_cookie}; HttpOnly; SameSite=Strict; Path=/"
            if self.services.secure_cookies:
                attrs += "; Secure"
            self.send_header("Set-Cookie", attrs)
        if clear_cookie:
            self.send_header(
                "Set-Cookie",
                f"{SESSION_COOKIE}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
            )
        self.end_headers()
        self.wfile.write(body)

    def _require_session(self, need_mfa: bool = True):
        token, session = self._session()
        if session is None:
            raise ApiError(401, "Sign in first.")
        if need_mfa and not session.mfa_passed:
            raise ApiError(403, "Complete your second factor first.")
        return token, session

    def _require_csrf(self, session) -> None:
        presented = self.headers.get("X-CSRF-Token")
        if not self.services.sessions.check_csrf(session, presented):
            # A missing or wrong token means the request did not come from our
            # own page, whatever the cookie says.
            raise ApiError(403, "That request could not be verified as yours.")

    # ---- routing -------------------------------------------------------

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            if path == "/api/me":
                return self._get_me()
            return self._serve_static(path)
        except ApiError as error:
            self._send_json(error.status, {"error": error.message},
                            retry_after=error.retry_after)

    def do_POST(self):
        path = urlparse(self.path).path
        routes = {
            "/api/accounts": self._post_account,
            "/api/sign-in": self._post_sign_in,
            "/api/sign-out": self._post_sign_out,
            "/api/mfa/enrol": self._post_mfa_enrol,
            "/api/mfa/confirm": self._post_mfa_confirm,
            "/api/mfa/verify": self._post_mfa_verify,
            "/api/works": self._post_work,
            "/api/email/send-verification": self._post_send_verification,
            "/api/email/verify": self._post_verify_email,
            "/api/password/forgot": self._post_forgot_password,
            "/api/password/reset": self._post_reset_password,
            "/api/recovery/codes": self._post_recovery_codes,
            "/api/recovery/use": self._post_use_recovery_code,
            "/api/domain/challenge": self._post_domain_challenge,
            "/api/domain/verify": self._post_domain_verify,
        }
        handler = routes.get(path)
        if handler is None:
            return self._send_json(404, {"error": "No such endpoint."})
        try:
            handler()
        except ApiError as error:
            self._send_json(error.status, {"error": error.message},
                            retry_after=error.retry_after)
        except (AccountError, RecordError, FingerprintError) as error:
            self._send_json(400, {"error": str(error)})

    # ---- endpoints -----------------------------------------------------

    def _get_me(self):
        _, session = self._session()
        if session is None:
            return self._send_json(200, {"signed_in": False})
        account = self.services.accounts.by_identity(session.identity_id)
        if account is None:
            return self._send_json(200, {"signed_in": False})
        self._send_json(200, {
            "signed_in": True,
            "identity_id": account.identity_id,
            "email": account.email,
            "assurance_level": str(account.assurance_level),
            "mfa_state": str(account.mfa_state),
            "mfa_passed": session.mfa_passed,
            "may_register_works": account.may_register_works and session.mfa_passed,
            "csrf_token": session.csrf_token,
        })

    def _post_account(self):
        decision = self.services.limiter.consume(ACCOUNT_CREATION, _client_key(self))
        if not decision.allowed:
            raise ApiError(429, "Too many accounts created from here.",
                           decision.retry_after)
        body = self._json_body()
        account = self.services.accounts.create(
            body.get("email", ""), body.get("password", "")
        )
        token = self.services.sessions.create(account.identity_id, mfa_passed=False)
        self._send_json(201, {
            "identity_id": account.identity_id,
            "next": "enrol-mfa",
        }, set_cookie=token)

    def _post_sign_in(self):
        decision = self.services.limiter.consume(SIGN_IN, _client_key(self))
        if not decision.allowed:
            raise ApiError(429, "Too many sign-in attempts.", decision.retry_after)

        body = self._json_body()
        account = self.services.accounts.authenticate(
            body.get("email", ""), body.get("password", "")
        )
        if account is None:
            # One message for both wrong password and unknown address, so the
            # response does not reveal which addresses are registered.
            raise ApiError(401, "That email address and password do not match.")

        self.services.limiter.clear(SIGN_IN, _client_key(self))
        # A session is issued without MFA passed even when the account has an
        # active factor: it can do nothing until the factor is presented.
        token = self.services.sessions.create(account.identity_id, mfa_passed=False)
        self._send_json(200, {
            "next": "verify-mfa" if account.mfa_state is MfaState.ACTIVE else "enrol-mfa",
        }, set_cookie=token)

    def _post_sign_out(self):
        token, session = self._session()
        if token:
            self.services.sessions.revoke(token)
        self._send_json(200, {"signed_out": True}, clear_cookie=True)

    def _post_mfa_enrol(self):
        token, session = self._require_session(need_mfa=False)
        self._require_csrf(session)
        account = self.services.accounts.by_identity(session.identity_id)
        if account.mfa_state is MfaState.ACTIVE:
            raise ApiError(409, "A second factor is already active on this account.")
        secret = self.services.accounts.begin_mfa_enrolment(session.identity_id)
        self._send_json(200, {"otpauth_uri": totp_uri(account.email, secret)})

    def _post_mfa_confirm(self):
        token, session = self._require_session(need_mfa=False)
        self._require_csrf(session)
        decision = self.services.limiter.consume(MFA_ATTEMPT, session.identity_id)
        if not decision.allowed:
            raise ApiError(429, "Too many codes tried.", decision.retry_after)
        if not self.services.accounts.confirm_mfa(
            session.identity_id, str(self._json_body().get("code", ""))
        ):
            raise ApiError(401, "That code is not right.")
        rotated = self.services.sessions.upgrade(token)
        self._send_json(200, {"mfa": "active"}, set_cookie=rotated)

    def _post_mfa_verify(self):
        token, session = self._require_session(need_mfa=False)
        self._require_csrf(session)
        decision = self.services.limiter.consume(MFA_ATTEMPT, session.identity_id)
        if not decision.allowed:
            raise ApiError(429, "Too many codes tried.", decision.retry_after)
        if not self.services.accounts.verify_totp(
            session.identity_id, str(self._json_body().get("code", ""))
        ):
            raise ApiError(401, "That code is not right.")
        rotated = self.services.sessions.upgrade(token)
        self._send_json(200, {"mfa": "passed"}, set_cookie=rotated)

    def _post_work(self):
        """Register a work. The only write path into the log."""
        token, session = self._require_session(need_mfa=True)
        self._require_csrf(session)

        account = self.services.accounts.by_identity(session.identity_id)
        if account is None or not account.may_register_works:
            raise ApiError(403, "This account cannot register works yet.")

        decision = self.services.limiter.consume(WORK_REGISTRATION, account.identity_id)
        if not decision.allowed:
            # The threat model's mass pre-emptive registration attack is exactly
            # someone submitting claims faster than a person creates work.
            raise ApiError(429, "Too many registrations in the last hour.",
                           decision.retry_after)

        body = self._json_body()
        fingerprints = tuple(
            Fingerprint(FingerprintKind(kind), value)
            for kind, value in sorted((body.get("fingerprints") or {}).items())
        )
        record = Record(
            content=Content(
                sha256=str(body.get("sha256", "")),
                media_type=str(body.get("media_type", "")),
                size_bytes=int(body.get("size_bytes", -1)),
                fingerprints=fingerprints,
                quality=body.get("quality"),
            ),
            issuer=Issuer(
                identity_id=account.identity_id,
                assurance_level=account.assurance_level,
                key_id="log-key-2026-09",
            ),
            claim_type=ClaimType(str(body.get("claim_type", "created"))),
            policy_version=1,
            declared_created_at=body.get("declared_created_at"),
        )
        entry = self.services.log.append(record)
        self._send_json(201, {
            "position": entry.position,
            "leaf_hash": entry.leaf_hash.hex(),
            "log_size": self.services.log.size(),
            "assurance_level": str(account.assurance_level),
            "note": "Awaiting the next published checkpoint before it can be verified.",
        })

    # ---- assurance ladder ----------------------------------------------

    def _post_send_verification(self):
        _, session = self._require_session(need_mfa=False)
        self._require_csrf(session)
        account = self.services.accounts.by_identity(session.identity_id)
        token = self.services.tokens.issue(
            account.identity_id, TokenPurpose.EMAIL_VERIFICATION
        )
        self.services.mailer.send(verification_message(
            account.email,
            f"{self.services.base_url}/verify-email.html?token={token.secret}",
        ))
        self._send_json(200, {"sent": True})

    def _post_verify_email(self):
        # No session required. The link arrives in an inbox that may be open on
        # a different device from the one that signed up.
        identity_id = self.services.tokens.redeem(
            str(self._json_body().get("token", "")), TokenPurpose.EMAIL_VERIFICATION
        )
        if identity_id is None:
            raise ApiError(400, "That link is not valid, or it has already been used.")
        account = self.services.accounts.mark_email_verified(identity_id)
        self._send_json(200, {"assurance_level": str(account.assurance_level)})

    def _post_domain_challenge(self):
        _, session = self._require_session()
        self._require_csrf(session)
        try:
            domain = normalise_domain(str(self._json_body().get("domain", "")))
        except DomainError as error:
            raise ApiError(400, str(error))
        challenge = challenge_for(session.identity_id, domain, self.services.domain_secret)
        self._send_json(200, {
            "domain": challenge.domain,
            "record_name": challenge.record_name,
            "record_value": challenge.record_value,
            "instructions": challenge.instructions,
        })

    def _post_domain_verify(self):
        _, session = self._require_session()
        self._require_csrf(session)
        account = self.services.accounts.by_identity(session.identity_id)
        # The ladder is climbed in order. A domain proof is the stronger claim,
        # but it is not a substitute for being reachable: alerts about work that
        # resembles yours, and every recovery path, go to a confirmed address.
        # Allowing the skip would also let the level assert an email check that
        # never happened.
        if account.assurance_level is AssuranceLevel.UNVERIFIED:
            raise ApiError(
                403,
                "Confirm your email address first. A domain proof is the stronger "
                "claim, but it does not make the account reachable.",
            )
        # Keyed by account, not address: this endpoint spends outbound requests
        # to resolvers we do not run, and a session is already required.
        decision = self.services.limiter.consume(DOMAIN_CHECK, account.identity_id)
        if not decision.allowed:
            raise ApiError(429, "Too many domain checks.", decision.retry_after)
        # Normalised outside the lookup, so a malformed domain stays a client
        # error rather than being reported as our resolvers being unavailable.
        try:
            domain = normalise_domain(str(self._json_body().get("domain", "")))
        except DomainError as error:
            raise ApiError(400, str(error))
        challenge = challenge_for(account.identity_id, domain, self.services.domain_secret)
        try:
            proved = verify_domain(challenge, self.services.resolver)
        except DomainError as error:
            # A lookup that did not complete is not a failed proof, and saying
            # so keeps a DNS outage from reading as "you do not own this".
            raise ApiError(503, str(error))
        if not proved:
            raise ApiError(
                400,
                "The resolvers answered, and that record was not among what they agreed on.",
            )
        self.services.accounts.set_assurance(account.identity_id, AssuranceLevel.DOMAIN)
        self._send_json(200, {"assurance_level": "domain", "domain": domain})

    # ---- recovery ------------------------------------------------------

    def _post_forgot_password(self):
        decision = self.services.limiter.consume(SIGN_IN, _client_key(self))
        if not decision.allowed:
            raise ApiError(429, "Too many attempts.", decision.retry_after)
        email = str(self._json_body().get("email", "")).strip().lower()
        account = self.services.accounts.by_email(email)
        if account is None:
            # Something is always sent, and the response is always the same.
            # Silence for an unregistered address would itself answer whether
            # it is registered.
            if email:
                self.services.mailer.send(no_account_message(email))
        else:
            token = self.services.tokens.issue(
                account.identity_id, TokenPurpose.PASSWORD_RESET
            )
            self.services.mailer.send(password_reset_message(
                account.email,
                f"{self.services.base_url}/reset-password.html?token={token.secret}",
            ))
        self._send_json(200, {"sent": True})

    def _post_reset_password(self):
        body = self._json_body()
        password = str(body.get("password", ""))
        # Validated before the token is redeemed. Redeeming first meant a
        # password that was merely too short consumed the single-use link and
        # sent the user back for another one, which is a good way to train
        # people to request reset links repeatedly.
        if len(password) < MIN_PASSWORD_LENGTH:
            raise ApiError(
                400, f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
            )
        identity_id = self.services.tokens.redeem(
            str(body.get("token", "")), TokenPurpose.PASSWORD_RESET
        )
        if identity_id is None:
            raise ApiError(400, "That link is not valid, or it has already been used.")
        self.services.accounts.set_password(identity_id, password)
        # Every session ends. A reset is what someone does when they suspect
        # the account is compromised, and leaving other sessions alive would
        # defeat the point of it.
        self.services.sessions.revoke_all(identity_id)
        self._send_json(200, {
            "reset": True,
            "note": "Sign in again. Your second factor is still required.",
        })

    def _post_recovery_codes(self):
        _, session = self._require_session()
        self._require_csrf(session)
        codes = self.services.tokens.issue_recovery_codes(session.identity_id)
        # Returned once. They are stored hashed, so nothing can show them again.
        self._send_json(200, {"codes": codes, "shown_once": True})

    def _post_use_recovery_code(self):
        token, session = self._require_session(need_mfa=False)
        self._require_csrf(session)
        decision = self.services.limiter.consume(MFA_ATTEMPT, session.identity_id)
        if not decision.allowed:
            raise ApiError(429, "Too many attempts.", decision.retry_after)
        identity_id = self.services.tokens.redeem(
            str(self._json_body().get("code", "")), TokenPurpose.RECOVERY_CODE
        )
        if identity_id != session.identity_id:
            raise ApiError(401, "That recovery code is not valid.")
        account = self.services.accounts.by_identity(identity_id)
        # The authenticator is gone, which is why a code was used, so the old
        # secret goes with it and a fresh one must be enrolled.
        self.services.accounts.clear_mfa(identity_id)
        self.services.mailer.send(recovery_used_message(account.email))
        rotated = self.services.sessions.upgrade(token)
        self._send_json(200, {
            "recovered": True,
            "remaining_codes": self.services.tokens.remaining(
                identity_id, TokenPurpose.RECOVERY_CODE
            ),
            "next": "enrol-mfa",
        }, set_cookie=rotated)

    # ---- static --------------------------------------------------------

    def _serve_static(self, path: str):
        if path in ("", "/"):
            path = "/index.html"
        target = (self.services.web_root / path.lstrip("/")).resolve()
        root = self.services.web_root.resolve()
        # A path that escapes the web root is not a missing file, it is an
        # attempt, and it gets the same 404 either way.
        if not str(target).startswith(str(root)) or not target.is_file():
            return self._send_json(404, {"error": "Not found."})
        body = target.read_bytes()
        kind = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        for header, value in SECURITY_HEADERS.items():
            self.send_header(header, value)
        self.end_headers()
        self.wfile.write(body)


def serve(services: Services, port: int = 0) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"services": services})
    return ThreadingHTTPServer(("127.0.0.1", port), handler)
