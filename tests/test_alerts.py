"""Alert planning and delivery.

Most of these are about what must NOT be sent. An alert names a stranger to
someone already worried about being copied, so the interesting failures are all
over-delivery: telling someone twice, telling them about themselves, or letting
an attacker use the channel to bury a real alert under noise.
"""

import unittest

from certifiles.accounts import AccountStore
from certifiles.alerts import (
    DAY_SECONDS,
    MAX_ATTEMPTS,
    AlertStore,
    PendingAlert,
    alert_message,
    deliver,
    plan,
)
from certifiles.log import TransparencyLog
from certifiles.nearmatch import AlertPolicy, Band, NearMatchIndex
from certifiles.record import (
    AssuranceLevel,
    ClaimType,
    Content,
    Issuer,
    Record,
)
from certifiles.similarity import SimilarityFingerprint, SimilarityKind

BASE = "https://certifiles.example"


def fingerprint(value):
    return SimilarityFingerprint(SimilarityKind.PHASH, value)


def near(base_hex, flipped_bits):
    """A phash a known Hamming distance from `base_hex`."""
    return f"{int(base_hex, 16) ^ ((1 << flipped_bits) - 1):016x}"


class Mailbox:
    def __init__(self, fail=False):
        self.sent = []
        self.fail = fail

    def send(self, message):
        if self.fail:
            raise RuntimeError("smtp unavailable")
        self.sent.append(message)


class AlertTestCase(unittest.TestCase):
    def setUp(self):
        self.log = TransparencyLog()
        self.index = NearMatchIndex()
        self.store = AlertStore()
        self.accounts = AccountStore()
        for store in (self.log, self.index, self.store, self.accounts):
            self.addCleanup(store.close)
        self.mailbox = Mailbox()

    def register(self, identity, phash, sha=None):
        """Append a record and index it, the way the service does."""
        prints = (fingerprint(phash),)
        record = Record(
            content=Content(
                sha256=sha or f"{len(self.log_positions()):064x}",
                media_type="image/png",
                size_bytes=1024,
                similarity_fingerprints=prints,
                derivation_version=1,
            ),
            issuer=Issuer(identity, AssuranceLevel.EMAIL, "log-key-2026-09"),
            claim_type=ClaimType.CREATED,
            policy_version=1,
        )
        entry = self.log.append(record)
        self.index.add(entry.position, prints)
        return entry.position, prints

    def log_positions(self):
        return range(self.log.size())

    def account(self, email):
        return self.accounts.create(email, "correct horse battery staple")


class TestPlanning(AlertTestCase):
    def test_an_earlier_registrant_is_alerted_about_a_later_near_match(self):
        first, _ = self.register("opaque-identity-aaaa", "ffffffffffffffff")
        second, prints = self.register("opaque-identity-bbbb", near("ffffffffffffffff", 2))
        planned = plan(self.log, self.index, second, prints, None, "opaque-identity-bbbb")
        self.assertEqual(len(planned), 1)
        self.assertEqual(planned[0].recipient_identity, "opaque-identity-aaaa")
        self.assertEqual(planned[0].subject_position, first)
        self.assertEqual(planned[0].candidate_position, second)

    def test_nobody_is_alerted_about_their_own_registration(self):
        # Registering two versions of your own work is the most ordinary thing
        # an artist does. A product that emails you about yourself is broken on
        # first use.
        self.register("opaque-identity-aaaa", "ffffffffffffffff")
        second, prints = self.register("opaque-identity-aaaa", near("ffffffffffffffff", 2))
        self.assertEqual(
            plan(self.log, self.index, second, prints, None, "opaque-identity-aaaa"), []
        )

    def test_an_earlier_registration_alerts_nobody(self):
        # Only earlier registrants can be alerted: a later registration cannot
        # be the thing that was copied from.
        first, prints = self.register("opaque-identity-aaaa", "ffffffffffffffff")
        self.register("opaque-identity-bbbb", near("ffffffffffffffff", 2))
        self.assertEqual(
            plan(self.log, self.index, first, prints, None, "opaque-identity-aaaa"), []
        )

    def test_a_weak_candidate_does_not_reach_anyone(self):
        # The default floor is POSSIBLE. Weak matches are visible on the
        # dashboard for someone who went looking, and are not worth an email.
        self.register("opaque-identity-aaaa", "ffffffffffffffff")
        second, prints = self.register("opaque-identity-bbbb", near("ffffffffffffffff", 14))
        planned = plan(self.log, self.index, second, prints, None, "opaque-identity-bbbb")
        self.assertEqual([p.band for p in planned], [])

    def test_a_work_with_no_fingerprints_alerts_nobody(self):
        self.register("opaque-identity-aaaa", "ffffffffffffffff")
        self.assertEqual(plan(self.log, self.index, 1, (), None, "opaque-identity-bbbb"), [])

    def test_the_band_floor_is_configurable(self):
        self.register("opaque-identity-aaaa", "ffffffffffffffff")
        second, prints = self.register("opaque-identity-bbbb", near("ffffffffffffffff", 14))
        planned = plan(self.log, self.index, second, prints, None, "opaque-identity-bbbb",
                       AlertPolicy(minimum_band=Band.WEAK))
        self.assertEqual(len(planned), 1)


class TestQueue(AlertTestCase):
    def alert(self, recipient="opaque-identity-aaaa", subject=0, candidate=1):
        return PendingAlert(recipient, subject, candidate, "strong_candidate", {"phash": 2})

    def test_the_same_pair_is_never_queued_twice(self):
        self.assertEqual(self.store.queue([self.alert()]), 1)
        self.assertEqual(self.store.queue([self.alert()]), 0)
        self.assertEqual(len(self.store.undelivered()), 1)

    def test_a_sent_alert_is_not_returned_again(self):
        self.store.queue([self.alert()])
        self.store.mark_sent(self.store.undelivered())
        self.assertEqual(self.store.undelivered(), [])

    def test_an_alert_is_abandoned_after_enough_failures(self):
        self.store.queue([self.alert()])
        for _ in range(MAX_ATTEMPTS):
            self.store.mark_attempted(self.store.undelivered())
        self.assertEqual(self.store.undelivered(), [])
        self.assertEqual(self.store.abandoned(), 1)

    def test_distances_survive_the_round_trip(self):
        self.store.queue([PendingAlert("opaque-identity-aaaa", 0, 1, "possible",
                                       {"phash": 7, "dhash": 9})])
        self.assertEqual(self.store.undelivered()[0].distances, {"phash": 7, "dhash": 9})


class TestDelivery(AlertTestCase):
    def setUp(self):
        super().setUp()
        self.recipient = self.account("amara@example.com")

    def queue_one(self, subject=0, candidate=1):
        self.store.queue([PendingAlert(self.recipient.identity_id, subject, candidate,
                                       "strong_candidate", {"phash": 2})])

    def test_delivery_sends_and_marks(self):
        self.queue_one()
        self.assertEqual(
            deliver(self.store, self.accounts, self.mailbox, BASE), 1)
        self.assertEqual(len(self.mailbox.sent), 1)
        self.assertEqual(self.store.undelivered(), [])

    def test_several_alerts_become_one_message(self):
        # A separate email per match is how a real alert gets lost in a pile.
        for candidate in range(1, 5):
            self.queue_one(candidate=candidate)
        deliver(self.store, self.accounts, self.mailbox, BASE)
        self.assertEqual(len(self.mailbox.sent), 1)
        self.assertIn("4 registrations", self.mailbox.sent[0].subject)

    def test_a_failed_send_leaves_the_alert_queued(self):
        self.queue_one()
        self.assertEqual(
            deliver(self.store, self.accounts, Mailbox(fail=True), BASE), 0)
        self.assertEqual(len(self.store.undelivered()), 1)
        # And it goes out once the mail server is back.
        self.assertEqual(deliver(self.store, self.accounts, self.mailbox, BASE), 1)

    def test_an_unknown_account_does_not_wedge_the_queue(self):
        self.store.queue([PendingAlert("opaque-identity-gone", 0, 1, "possible", {})])
        for _ in range(MAX_ATTEMPTS):
            deliver(self.store, self.accounts, self.mailbox, BASE)
        self.assertEqual(self.store.undelivered(), [])
        self.assertEqual(self.mailbox.sent, [])

    def test_the_daily_cap_holds_alerts_back_rather_than_dropping_them(self):
        # The channel is attacker controlled: anyone can cause alerts by
        # registering near-matches to a chosen artist's work. Capping matters,
        # and so does the held-back alert still arriving eventually.
        policy = AlertPolicy(max_alerts_per_recipient_per_day=3)
        for candidate in range(1, 6):
            self.queue_one(candidate=candidate)
        now = 1_700_000_000
        deliver(self.store, self.accounts, self.mailbox, BASE, policy, now)
        self.assertEqual(len(self.store.undelivered()), 2)

        # Same day: still capped.
        deliver(self.store, self.accounts, self.mailbox, BASE, policy, now + 60)
        self.assertEqual(len(self.store.undelivered()), 2)

        # A day later the window has moved and the rest go out.
        deliver(self.store, self.accounts, self.mailbox, BASE, policy,
                now + DAY_SECONDS + 1)
        self.assertEqual(self.store.undelivered(), [])

    def test_two_recipients_get_their_own_messages(self):
        other = self.account("kenji@example.com")
        self.queue_one()
        self.store.queue([PendingAlert(other.identity_id, 5, 6, "possible", {"phash": 9})])
        self.assertEqual(deliver(self.store, self.accounts, self.mailbox, BASE), 2)
        self.assertEqual({m.to for m in self.mailbox.sent},
                         {"amara@example.com", "kenji@example.com"})


class TestWording(AlertTestCase):
    """The copy is the product here, so it is asserted rather than trusted."""

    def message(self, band="strong_candidate", count=1):
        alerts = [PendingAlert("opaque-identity-aaaa", 0, n + 1, band, {"phash": 2})
                  for n in range(count)]
        return alert_message("amara@example.com", BASE, alerts)

    def test_it_says_plainly_that_this_is_not_a_finding(self):
        body = self.message().body
        self.assertIn("not a finding", body)
        self.assertIn("coincidence", body)

    def test_it_never_asserts_that_anyone_copied_anything(self):
        body = self.message().body.lower()
        for phrase in ("stole", "stolen", "infringed", "copied your", "plagiar"):
            self.assertNotIn(phrase, body, f"the alert must not say {phrase!r}")

    def test_it_links_the_record_so_the_reader_can_look(self):
        self.assertIn(f"{BASE}/record.html?p=1", self.message().body)

    def test_the_subject_counts_correctly(self):
        self.assertIn("1 registration resembling", self.message(count=1).subject)
        self.assertIn("3 registrations resembling", self.message(count=3).subject)

    def test_a_weaker_band_is_worded_more_weakly(self):
        self.assertIn("Independent algorithms agree",
                      self.message("strong_candidate").body)
        self.assertIn("Close on some measures and not others",
                      self.message("possible").body)

    def test_the_subject_line_carries_no_line_break(self):
        # Message refuses one, but the count is interpolated, so assert the
        # property rather than relying on the constructor not having raised.
        subject = self.message(count=99).subject
        self.assertNotIn("\n", subject)
        self.assertNotIn("\r", subject)


if __name__ == "__main__":
    unittest.main()
