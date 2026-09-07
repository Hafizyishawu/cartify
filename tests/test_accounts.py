"""Account, session and rate limit tests.

These cover the paths an attacker gets unlimited attempts at, so most of them
check that something is refused rather than that it works.
"""

import sqlite3
import time
import unittest

from certifiles.accounts import (
    MIN_PASSWORD_LENGTH,
    TOTP_PERIOD,
    Account,
    AccountError,
    AccountStore,
    MfaState,
    hash_password,
    totp_code,
    totp_uri,
)
from certifiles.ratelimit import (
    ACCOUNT_CREATION,
    SIGN_IN,
    Limit,
    RateLimitError,
    RateLimiter,
)
from certifiles.record import AssuranceLevel
from certifiles.sessions import (
    PARTIAL_TTL_SECONDS,
    SESSION_TTL_SECONDS,
    SessionError,
    SessionStore,
)

PASSWORD = "correct horse battery staple"
EMAIL = "amara@example.com"


class AccountTestCase(unittest.TestCase):
    def setUp(self):
        self.store = AccountStore()
        self.addCleanup(self.store.close)


class TestPasswords(unittest.TestCase):
    def test_the_same_password_hashes_differently_each_time(self):
        # A shared salt would make one precomputation break every account.
        first, salt_a = hash_password(PASSWORD)
        second, salt_b = hash_password(PASSWORD)
        self.assertNotEqual(salt_a, salt_b)
        self.assertNotEqual(first, second)

    def test_the_same_salt_reproduces_the_hash(self):
        digest, salt = hash_password(PASSWORD)
        self.assertEqual(hash_password(PASSWORD, salt=salt)[0], digest)

    def test_short_passwords_are_refused(self):
        with self.assertRaises(AccountError):
            hash_password("x" * (MIN_PASSWORD_LENGTH - 1))

    def test_hashing_is_deliberately_slow(self):
        # The cost is the attacker's cost per guess against a stolen database.
        # If this ever drops to microseconds, the parameters were lost.
        started = time.perf_counter()
        hash_password(PASSWORD)
        self.assertGreater(time.perf_counter() - started, 0.01)


class TestAccountCreation(AccountTestCase):
    def test_creating_and_reading_back(self):
        account = self.store.create(EMAIL, PASSWORD)
        self.assertEqual(account.email, EMAIL)
        self.assertEqual(account.assurance_level, AssuranceLevel.UNVERIFIED)
        self.assertEqual(account.mfa_state, MfaState.NONE)

    def test_the_identity_id_is_not_derived_from_the_email(self):
        # A hash of the address would let anyone holding the published log test
        # whether a given person had registered anything.
        import hashlib

        account = self.store.create(EMAIL, PASSWORD)
        for candidate in (
            EMAIL,
            hashlib.sha256(EMAIL.encode()).hexdigest(),
            hashlib.sha256(EMAIL.encode()).hexdigest()[:16],
        ):
            self.assertNotIn(candidate, account.identity_id)

    def test_two_accounts_get_unrelated_identifiers(self):
        a = self.store.create("a@example.com", PASSWORD)
        b = self.store.create("b@example.com", PASSWORD)
        self.assertNotEqual(a.identity_id, b.identity_id)

    def test_the_identity_id_is_a_valid_log_identifier(self):
        # It goes straight into a record, which validates its shape.
        from certifiles.record import OPAQUE_ID_PATTERN

        account = self.store.create(EMAIL, PASSWORD)
        self.assertTrue(OPAQUE_ID_PATTERN.match(account.identity_id))

    def test_duplicate_addresses_are_refused(self):
        self.store.create(EMAIL, PASSWORD)
        with self.assertRaises(AccountError):
            self.store.create(EMAIL, PASSWORD)

    def test_addresses_are_normalised(self):
        self.store.create("  Amara@Example.COM ", PASSWORD)
        with self.assertRaises(AccountError):
            self.store.create("amara@example.com", PASSWORD)

    def test_malformed_addresses_are_refused(self):
        for bad in ("", "no-at-sign", "two@@example.com", "a@b", 7, None):
            with self.subTest(email=bad):
                with self.assertRaises(AccountError):
                    self.store.create(bad, PASSWORD)


class TestAuthentication(AccountTestCase):
    def setUp(self):
        super().setUp()
        self.account = self.store.create(EMAIL, PASSWORD)

    def test_the_right_password_authenticates(self):
        self.assertEqual(
            self.store.authenticate(EMAIL, PASSWORD).identity_id,
            self.account.identity_id,
        )

    def test_the_wrong_password_does_not(self):
        self.assertIsNone(self.store.authenticate(EMAIL, "wrong password here"))

    def test_an_unknown_address_returns_none_rather_than_raising(self):
        self.assertIsNone(self.store.authenticate("nobody@example.com", PASSWORD))

    def test_an_unknown_address_still_does_the_hashing_work(self):
        # Returning immediately would let an attacker enumerate registered
        # addresses by timing alone.
        started = time.perf_counter()
        self.store.authenticate("nobody@example.com", PASSWORD)
        self.assertGreater(time.perf_counter() - started, 0.01)

    def test_a_failed_attempt_is_recorded(self):
        self.store.authenticate(EMAIL, "wrong password here")
        events = [e for e, _, _ in self.store.events(self.account.identity_id)]
        self.assertIn("auth.failed", events)

    def test_the_audit_trail_cannot_be_edited(self):
        # Recovery is the softest path to everything an account owns, so the
        # record of it must not be editable by the code that performs it.
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute("DELETE FROM account_events")
        with self.assertRaises(sqlite3.IntegrityError):
            self.store._connection.execute("UPDATE account_events SET event = 'x'")


class TestSecondFactor(AccountTestCase):
    def setUp(self):
        super().setUp()
        self.account = self.store.create(EMAIL, PASSWORD)
        self.secret = self.store.begin_mfa_enrolment(self.account.identity_id)
        self.now = 1_700_000_000

    def code(self, at=None):
        return totp_code(self.secret, int((at or self.now) // TOTP_PERIOD))

    def test_a_correct_code_activates_the_factor(self):
        self.assertTrue(
            self.store.confirm_mfa(self.account.identity_id, self.code(), now=self.now)
        )
        self.assertEqual(
            self.store.by_identity(self.account.identity_id).mfa_state, MfaState.ACTIVE
        )

    def test_a_wrong_code_does_not(self):
        self.assertFalse(
            self.store.confirm_mfa(self.account.identity_id, "000000", now=self.now)
        )

    def test_a_code_cannot_be_used_twice(self):
        # Otherwise a code seen in transit stays valid for the rest of its
        # window, which is the whole window an attacker needs.
        self.store.confirm_mfa(self.account.identity_id, self.code(), now=self.now)
        self.assertFalse(
            self.store.verify_totp(self.account.identity_id, self.code(), now=self.now)
        )
        events = [e for e, _, _ in self.store.events(self.account.identity_id)]
        self.assertIn("mfa.replay_rejected", events)

    def test_a_code_from_the_previous_step_is_accepted_once(self):
        earlier = self.now - TOTP_PERIOD
        self.assertTrue(
            self.store.confirm_mfa(
                self.account.identity_id, self.code(earlier), now=self.now
            )
        )

    def test_a_code_far_outside_the_window_is_refused(self):
        self.assertFalse(
            self.store.confirm_mfa(
                self.account.identity_id, self.code(self.now - 600), now=self.now
            )
        )

    def test_a_pending_factor_cannot_authorise_anything(self):
        # Enrolment started but never confirmed must not grant authority.
        self.assertFalse(
            self.store.verify_totp(self.account.identity_id, self.code(), now=self.now)
        )

    def test_non_numeric_codes_are_refused(self):
        for bad in ("abcdef", "", None, 123456):
            with self.subTest(code=bad):
                self.assertFalse(
                    self.store.verify_totp(self.account.identity_id, bad, now=self.now)
                )

    def test_registering_works_requires_an_active_factor(self):
        account = self.store.by_identity(self.account.identity_id)
        self.assertFalse(account.may_register_works)
        self.store.confirm_mfa(self.account.identity_id, self.code(), now=self.now)
        self.assertTrue(
            self.store.by_identity(self.account.identity_id).may_register_works
        )

    def test_the_enrolment_uri_carries_the_secret(self):
        uri = totp_uri(EMAIL, self.secret)
        self.assertTrue(uri.startswith("otpauth://totp/Certifiles:"))
        self.assertIn("digits=6", uri)


class TestAssurance(AccountTestCase):
    def test_assurance_can_be_raised(self):
        account = self.store.create(EMAIL, PASSWORD)
        self.store.set_assurance(account.identity_id, AssuranceLevel.DOMAIN)
        self.assertEqual(
            self.store.by_identity(account.identity_id).assurance_level,
            AssuranceLevel.DOMAIN,
        )

    def test_a_change_is_audited(self):
        account = self.store.create(EMAIL, PASSWORD)
        self.store.set_assurance(account.identity_id, AssuranceLevel.DOMAIN)
        events = [e for e, _, _ in self.store.events(account.identity_id)]
        self.assertIn("assurance.changed", events)


class TestSessions(unittest.TestCase):
    def setUp(self):
        self.store = SessionStore()
        self.addCleanup(self.store.close)
        self.now = 1_700_000_000

    def test_a_session_resolves(self):
        token = self.store.create("acct-1", mfa_passed=True, now=self.now)
        session = self.store.resolve(token, now=self.now)
        self.assertEqual(session.identity_id, "acct-1")
        self.assertTrue(session.mfa_passed)

    def test_the_token_is_never_stored(self):
        # A leaked database must not yield usable sessions.
        token = self.store.create("acct-1", now=self.now)
        rows = self.store._connection.execute("SELECT token_hash FROM sessions").fetchall()
        for (stored,) in rows:
            self.assertNotIn(token.encode(), stored)

    def test_an_unknown_token_resolves_to_nothing(self):
        for bad in ("", None, "not-a-token", 7):
            with self.subTest(token=bad):
                self.assertIsNone(self.store.resolve(bad, now=self.now))

    def test_a_partial_session_expires_sooner_than_a_full_one(self):
        partial = self.store.create("acct-1", mfa_passed=False, now=self.now)
        full = self.store.create("acct-2", mfa_passed=True, now=self.now)
        after = self.now + PARTIAL_TTL_SECONDS + 1
        self.assertIsNone(self.store.resolve(partial, now=after))
        self.assertIsNotNone(self.store.resolve(full, now=after))

    def test_an_expired_session_is_gone(self):
        token = self.store.create("acct-1", mfa_passed=True, now=self.now)
        self.assertIsNone(self.store.resolve(token, now=self.now + SESSION_TTL_SECONDS))

    def test_passing_the_second_factor_rotates_the_token(self):
        # A token captured before the second factor must not inherit the
        # authority granted after it. This is session fixation.
        first = self.store.create("acct-1", mfa_passed=False, now=self.now)
        second = self.store.upgrade(first, now=self.now)
        self.assertNotEqual(first, second)
        self.assertIsNone(self.store.resolve(first, now=self.now))
        self.assertTrue(self.store.resolve(second, now=self.now).mfa_passed)

    def test_upgrading_an_unknown_session_is_refused(self):
        with self.assertRaises(SessionError):
            self.store.upgrade("nope", now=self.now)

    def test_revoking_one_and_all(self):
        a = self.store.create("acct-1", now=self.now)
        b = self.store.create("acct-1", now=self.now)
        self.store.revoke(a)
        self.assertIsNone(self.store.resolve(a, now=self.now))
        self.assertIsNotNone(self.store.resolve(b, now=self.now))
        self.assertEqual(self.store.revoke_all("acct-1"), 1)
        self.assertIsNone(self.store.resolve(b, now=self.now))

    def test_csrf_tokens_are_per_session_and_compared_exactly(self):
        a = self.store.resolve(self.store.create("acct-1", now=self.now), now=self.now)
        b = self.store.resolve(self.store.create("acct-2", now=self.now), now=self.now)
        self.assertNotEqual(a.csrf_token, b.csrf_token)
        self.assertTrue(self.store.check_csrf(a, a.csrf_token))
        self.assertFalse(self.store.check_csrf(a, b.csrf_token))
        for bad in ("", None, a.csrf_token + "x", a.csrf_token[:-1]):
            with self.subTest(token=bad):
                self.assertFalse(self.store.check_csrf(a, bad))

    def test_csrf_never_passes_without_a_session(self):
        self.assertFalse(self.store.check_csrf(None, "anything"))

    def test_purging_removes_only_expired_sessions(self):
        old = self.store.create("acct-1", mfa_passed=True, now=self.now)
        new = self.store.create("acct-2", mfa_passed=True, now=self.now + 10_000)
        self.assertEqual(self.store.purge_expired(now=self.now + SESSION_TTL_SECONDS + 1), 1)
        self.assertIsNotNone(self.store.resolve(new, now=self.now + 10_001))


class TestRateLimiting(unittest.TestCase):
    def setUp(self):
        self.limiter = RateLimiter()
        self.addCleanup(self.limiter.close)
        self.now = 1_700_000_000

    def test_attempts_are_allowed_up_to_the_limit(self):
        for n in range(SIGN_IN.allowed):
            with self.subTest(attempt=n):
                self.assertTrue(self.limiter.consume(SIGN_IN, "ip", now=self.now).allowed)
        self.assertFalse(self.limiter.consume(SIGN_IN, "ip", now=self.now).allowed)

    def test_keys_are_independent(self):
        for _ in range(SIGN_IN.allowed):
            self.limiter.consume(SIGN_IN, "ip-a", now=self.now)
        self.assertTrue(self.limiter.consume(SIGN_IN, "ip-b", now=self.now).allowed)

    def test_buckets_are_independent(self):
        for _ in range(SIGN_IN.allowed):
            self.limiter.consume(SIGN_IN, "ip", now=self.now)
        self.assertTrue(self.limiter.consume(ACCOUNT_CREATION, "ip", now=self.now).allowed)

    def test_the_window_slides_rather_than_resetting(self):
        # A fixed window lets an attacker spend the whole budget at the end of
        # one and the whole budget at the start of the next.
        for _ in range(SIGN_IN.allowed):
            self.limiter.consume(SIGN_IN, "ip", now=self.now)
        just_inside = self.now + SIGN_IN.window_seconds - 1
        self.assertFalse(self.limiter.check(SIGN_IN, "ip", now=just_inside).allowed)
        just_outside = self.now + SIGN_IN.window_seconds + 1
        self.assertTrue(self.limiter.check(SIGN_IN, "ip", now=just_outside).allowed)

    def test_a_refused_attempt_still_counts(self):
        # Being blocked must not reset the window for the next try.
        for _ in range(SIGN_IN.allowed + 3):
            self.limiter.consume(SIGN_IN, "ip", now=self.now)
        later = self.now + SIGN_IN.window_seconds - 1
        self.assertFalse(self.limiter.check(SIGN_IN, "ip", now=later).allowed)

    def test_retry_after_is_reported_when_blocked(self):
        for _ in range(SIGN_IN.allowed):
            self.limiter.consume(SIGN_IN, "ip", now=self.now)
        decision = self.limiter.check(SIGN_IN, "ip", now=self.now)
        self.assertFalse(decision.allowed)
        self.assertGreater(decision.retry_after, 0)

    def test_a_successful_sign_in_can_clear_the_key(self):
        for _ in range(SIGN_IN.allowed):
            self.limiter.consume(SIGN_IN, "ip", now=self.now)
        self.limiter.clear(SIGN_IN, "ip")
        self.assertTrue(self.limiter.check(SIGN_IN, "ip", now=self.now).allowed)

    def test_a_nonsense_limit_is_refused(self):
        for allowed, window in ((0, 60), (-1, 60), (5, 0), (5, -60)):
            with self.subTest(allowed=allowed, window=window):
                with self.assertRaises(RateLimitError):
                    Limit("bad", allowed, window)


if __name__ == "__main__":
    unittest.main()
