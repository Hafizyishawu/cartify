"""Assurance ladder, email delivery and account recovery.

The recovery flow is the softest path to everything an account owns, so most of
these check that a step cannot be skipped.
"""

import unittest

from certifiles.accounts import AccountStore, MfaState, totp_code
from certifiles.domains import (
    Challenge,
    DomainError,
    challenge_for,
    new_server_secret,
    normalise_domain,
    verify,
)
from certifiles.mail import (
    FileMailer,
    MailError,
    Message,
    no_account_message,
    password_reset_message,
    verification_message,
)
from certifiles.record import AssuranceLevel
from certifiles.tokens import (
    LIFETIMES,
    RECOVERY_CODE_COUNT,
    TokenError,
    TokenPurpose,
    TokenStore,
)

EMAIL = "amara@example.com"
PASSWORD = "correct horse battery staple"


class FakeResolver:
    def __init__(self, records=None, fail=False):
        self.records = records or {}
        self.fail = fail

    def txt(self, name):
        if self.fail:
            raise RuntimeError("SERVFAIL")
        return self.records.get(name, [])


class TestTokens(unittest.TestCase):
    def setUp(self):
        self.store = TokenStore()
        self.addCleanup(self.store.close)
        self.now = 1_700_000_000

    def test_a_token_redeems_once(self):
        token = self.store.issue("acct", TokenPurpose.PASSWORD_RESET, now=self.now)
        self.assertEqual(
            self.store.redeem(token.secret, TokenPurpose.PASSWORD_RESET, now=self.now),
            "acct",
        )
        self.assertIsNone(
            self.store.redeem(token.secret, TokenPurpose.PASSWORD_RESET, now=self.now)
        )

    def test_the_secret_is_never_stored(self):
        token = self.store.issue("acct", TokenPurpose.PASSWORD_RESET, now=self.now)
        rows = self.store._connection.execute("SELECT token_hash FROM tokens").fetchall()
        for (stored,) in rows:
            self.assertNotIn(token.secret.encode(), stored)

    def test_a_token_expires(self):
        token = self.store.issue("acct", TokenPurpose.PASSWORD_RESET, now=self.now)
        expired = self.now + LIFETIMES[TokenPurpose.PASSWORD_RESET] + 1
        self.assertIsNone(
            self.store.redeem(token.secret, TokenPurpose.PASSWORD_RESET, now=expired)
        )

    def test_a_reset_link_is_shorter_lived_than_a_verification_link(self):
        # They do not grant the same thing, so they do not last the same time.
        self.assertLess(
            LIFETIMES[TokenPurpose.PASSWORD_RESET],
            LIFETIMES[TokenPurpose.EMAIL_VERIFICATION],
        )

    def test_a_token_cannot_be_redeemed_for_another_purpose(self):
        # Otherwise a verification link, which is longer lived, becomes a
        # password reset.
        token = self.store.issue("acct", TokenPurpose.EMAIL_VERIFICATION, now=self.now)
        self.assertIsNone(
            self.store.redeem(token.secret, TokenPurpose.PASSWORD_RESET, now=self.now)
        )

    def test_issuing_supersedes_the_previous_token(self):
        first = self.store.issue("acct", TokenPurpose.PASSWORD_RESET, now=self.now)
        self.store.issue("acct", TokenPurpose.PASSWORD_RESET, now=self.now)
        self.assertIsNone(
            self.store.redeem(first.secret, TokenPurpose.PASSWORD_RESET, now=self.now)
        )

    def test_garbage_redeems_to_nothing(self):
        for bad in ("", None, 7, "not-a-token"):
            with self.subTest(secret=bad):
                self.assertIsNone(
                    self.store.redeem(bad, TokenPurpose.PASSWORD_RESET, now=self.now)
                )

    def test_recovery_codes_come_as_a_set_and_each_works_once(self):
        codes = self.store.issue_recovery_codes("acct", now=self.now)
        self.assertEqual(len(codes), RECOVERY_CODE_COUNT)
        self.assertEqual(len(set(codes)), RECOVERY_CODE_COUNT)
        self.assertEqual(
            self.store.redeem(codes[0], TokenPurpose.RECOVERY_CODE, now=self.now), "acct"
        )
        self.assertIsNone(
            self.store.redeem(codes[0], TokenPurpose.RECOVERY_CODE, now=self.now)
        )
        self.assertEqual(
            self.store.remaining("acct", TokenPurpose.RECOVERY_CODE),
            RECOVERY_CODE_COUNT - 1,
        )

    def test_recovery_codes_do_not_expire(self):
        # They exist for discovering months later that a phone is gone.
        codes = self.store.issue_recovery_codes("acct", now=self.now)
        far_future = self.now + 400 * 24 * 3600
        self.assertEqual(
            self.store.redeem(codes[0], TokenPurpose.RECOVERY_CODE, now=far_future),
            "acct",
        )

    def test_regenerating_codes_invalidates_the_old_set(self):
        old = self.store.issue_recovery_codes("acct", now=self.now)
        self.store.issue_recovery_codes("acct", now=self.now)
        self.assertIsNone(
            self.store.redeem(old[0], TokenPurpose.RECOVERY_CODE, now=self.now)
        )

    def test_a_recovery_code_cannot_be_issued_as_a_single_token(self):
        with self.assertRaises(TokenError):
            self.store.issue("acct", TokenPurpose.RECOVERY_CODE, now=self.now)


class TestMail(unittest.TestCase):
    def test_a_header_cannot_carry_a_line_break(self):
        # Otherwise a subject becomes an extra header, which is how a message
        # acquires a bcc.
        for fields in ({"to": "a@b.com\nBcc: c@d.com", "subject": "s"},
                       {"to": "a@b.com", "subject": "hi\nBcc: c@d.com"},
                       {"to": "a@b.com\rBcc: c@d.com", "subject": "s"}):
            with self.subTest(**fields):
                with self.assertRaises(MailError):
                    Message(body="b", **fields)

    def test_the_file_mailer_writes_rather_than_sends(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            mailer = FileMailer(directory)
            mailer.send(Message("a@b.com", "Subject", "Body"))
            self.assertEqual(len(mailer.sent), 1)
            written = list(__import__("pathlib").Path(directory).iterdir())
            self.assertEqual(len(written), 1)
            self.assertIn("Body", written[0].read_text())

    def test_a_reset_message_says_mfa_is_still_required(self):
        # Someone with inbox access alone must not believe they can take the
        # account, and must not be surprised at the next step either.
        body = password_reset_message("a@b.com", "https://x/reset?token=t").body
        self.assertIn("second factor", body)
        self.assertIn("30 minutes", body)

    def test_the_unknown_address_message_exists_at_all(self):
        # Silence would answer the question of whether an address is
        # registered, so something is always sent.
        message = no_account_message("nobody@example.com")
        self.assertIn("no account", message.body.lower())

    def test_both_reset_messages_share_a_subject(self):
        # The subject is visible to anyone watching the mailbox from outside.
        self.assertEqual(
            password_reset_message("a@b.com", "https://x").subject,
            no_account_message("a@b.com").subject,
        )

    def test_a_verification_message_says_records_are_not_backdated(self):
        body = verification_message("a@b.com", "https://x").body
        self.assertIn("Existing records keep the level", body)


class TestDomains(unittest.TestCase):
    def setUp(self):
        self.secret = new_server_secret()

    def test_domains_are_normalised(self):
        for raw in ("Example.COM", "  example.com ", "https://example.com/path",
                    "www.example.com", "example.com."):
            with self.subTest(raw=raw):
                self.assertEqual(normalise_domain(raw), "example.com")

    def test_nonsense_is_refused(self):
        for bad in ("", "not a domain", "example", ".com", 7, "a" * 300 + ".com"):
            with self.subTest(domain=bad):
                with self.assertRaises(DomainError):
                    normalise_domain(bad)

    def test_a_challenge_is_stable_for_one_account_and_domain(self):
        first = challenge_for("acct", "example.com", self.secret)
        second = challenge_for("acct", "example.com", self.secret)
        self.assertEqual(first.record_value, second.record_value)

    def test_two_accounts_get_different_challenges_for_one_domain(self):
        # Otherwise anyone could compute the value a domain's real owner will
        # publish, and claim the domain the moment they do.
        a = challenge_for("acct-a", "example.com", self.secret)
        b = challenge_for("acct-b", "example.com", self.secret)
        self.assertNotEqual(a.record_value, b.record_value)

    def test_the_challenge_lives_at_a_dedicated_name(self):
        challenge = challenge_for("acct", "example.com", self.secret)
        self.assertEqual(challenge.record_name, "_certifiles.example.com")

    def test_the_published_record_proves_control(self):
        challenge = challenge_for("acct", "example.com", self.secret)
        resolver = FakeResolver({challenge.record_name: [challenge.record_value]})
        self.assertTrue(verify(challenge, resolver))

    def test_an_absent_or_wrong_record_does_not(self):
        challenge = challenge_for("acct", "example.com", self.secret)
        self.assertFalse(verify(challenge, FakeResolver({})))
        self.assertFalse(
            verify(challenge, FakeResolver({challenge.record_name: ["something else"]}))
        )

    def test_a_record_that_merely_contains_the_value_does_not_prove_control(self):
        # A substring match would accept a value published alongside anyone
        # else's content.
        challenge = challenge_for("acct", "example.com", self.secret)
        resolver = FakeResolver({
            challenge.record_name: [f"v=spf1 {challenge.record_value} extra"]
        })
        self.assertFalse(verify(challenge, resolver))

    def test_another_accounts_record_does_not_prove_control(self):
        mine = challenge_for("acct-a", "example.com", self.secret)
        theirs = challenge_for("acct-b", "example.com", self.secret)
        self.assertFalse(
            verify(mine, FakeResolver({mine.record_name: [theirs.record_value]}))
        )

    def test_a_lookup_failure_is_not_a_failed_proof(self):
        # A DNS outage must not read as "you do not own this domain".
        challenge = challenge_for("acct", "example.com", self.secret)
        with self.assertRaises(DomainError):
            verify(challenge, FakeResolver(fail=True))


class TestAssuranceLadder(unittest.TestCase):
    def setUp(self):
        self.store = AccountStore()
        self.addCleanup(self.store.close)
        self.account = self.store.create(EMAIL, PASSWORD)

    def test_a_new_account_starts_unverified(self):
        self.assertEqual(self.account.assurance_level, AssuranceLevel.UNVERIFIED)

    def test_verifying_an_email_raises_assurance(self):
        updated = self.store.mark_email_verified(self.account.identity_id)
        self.assertEqual(updated.assurance_level, AssuranceLevel.EMAIL)

    def test_verifying_an_email_never_lowers_assurance(self):
        # An account that has proven domain control must not be demoted by
        # confirming an address afterwards.
        self.store.set_assurance(self.account.identity_id, AssuranceLevel.DOMAIN)
        updated = self.store.mark_email_verified(self.account.identity_id)
        self.assertEqual(updated.assurance_level, AssuranceLevel.DOMAIN)

    def test_raising_assurance_does_not_reach_back_into_the_log(self):
        # A record keeps the assurance it was issued under, permanently.
        from certifiles.log import TransparencyLog
        from certifiles.record import ClaimType, Content, Issuer, Record

        log = TransparencyLog()
        self.addCleanup(log.close)
        before = self.store.by_identity(self.account.identity_id)
        log.append(Record(
            Content("a" * 64, "image/png", 10),
            Issuer(before.identity_id, before.assurance_level, "k"),
            ClaimType.CREATED, 1,
        ))
        self.store.set_assurance(self.account.identity_id, AssuranceLevel.DOMAIN)
        import json

        recorded = json.loads(log.entry(0).leaf_data.decode())
        self.assertEqual(recorded["issuer"]["assurance_level"], "unverified")

    def test_changes_are_audited(self):
        self.store.mark_email_verified(self.account.identity_id)
        events = [e for e, _, _ in self.store.events(self.account.identity_id)]
        self.assertIn("email.verified", events)


class TestPasswordAndMfaReset(unittest.TestCase):
    def setUp(self):
        self.store = AccountStore()
        self.addCleanup(self.store.close)
        self.account = self.store.create(EMAIL, PASSWORD)
        self.now = 1_700_000_000

    def test_a_new_password_replaces_the_old_one(self):
        self.store.set_password(self.account.identity_id, "a whole new passphrase")
        self.assertIsNone(self.store.authenticate(EMAIL, PASSWORD))
        self.assertIsNotNone(self.store.authenticate(EMAIL, "a whole new passphrase"))

    def test_a_password_change_is_audited(self):
        self.store.set_password(self.account.identity_id, "a whole new passphrase")
        events = [e for e, _, _ in self.store.events(self.account.identity_id)]
        self.assertIn("password.changed", events)

    def test_a_password_reset_does_not_clear_the_second_factor(self):
        # If it did, anyone with inbox access could take the account, and the
        # second factor would protect nothing.
        secret = self.store.begin_mfa_enrolment(self.account.identity_id)
        code = totp_code(secret, int(self.now // 30))
        self.store.confirm_mfa(self.account.identity_id, code, now=self.now)
        self.store.set_password(self.account.identity_id, "a whole new passphrase")
        self.assertEqual(
            self.store.by_identity(self.account.identity_id).mfa_state, MfaState.ACTIVE
        )

    def test_recovery_clears_the_factor_so_a_fresh_one_must_be_enrolled(self):
        # Recovery is used when the authenticator is gone, so keeping the old
        # secret would leave the account depending on something unreachable.
        secret = self.store.begin_mfa_enrolment(self.account.identity_id)
        self.store.confirm_mfa(
            self.account.identity_id, totp_code(secret, int(self.now // 30)), now=self.now
        )
        self.store.clear_mfa(self.account.identity_id)
        account = self.store.by_identity(self.account.identity_id)
        self.assertEqual(account.mfa_state, MfaState.NONE)
        self.assertFalse(account.may_register_works)

    def test_lookup_by_email_finds_the_account(self):
        self.assertEqual(
            self.store.by_email(EMAIL).identity_id, self.account.identity_id
        )
        self.assertIsNone(self.store.by_email("nobody@example.com"))


if __name__ == "__main__":
    unittest.main()
