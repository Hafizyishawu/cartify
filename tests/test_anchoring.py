"""Anchoring tests.

The property under test is the backdating bound: which records an anchor
actually covers, and which it does not. An off-by-one here would claim an
anchor vouches for a record entered after it, which is the backdating anchors
exist to prevent.
"""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from certifiles.anchoring import (
    AnchorError,
    AnchorKind,
    AnchorLedger,
    AnchorReceipt,
    DirectoryAnchor,
    backdating_bound,
    diverged,
    due_at,
    evidence_only,
    is_stale,
    latest_attested,
)
from certifiles.checkpoint import Checkpoint

HOUR = 3600
ROOT_A = bytes(range(32))
ROOT_B = bytes(range(32, 64))


def receipt(size, claimed, attested=None, root=ROOT_A, kind=AnchorKind.RFC3161):
    return AnchorReceipt(
        kind=kind,
        checkpoint_size=size,
        checkpoint_root=root,
        claimed_at=claimed,
        receipt=b"opaque-token",
        attested_at=attested,
    )


class TestReceipt(unittest.TestCase):
    def test_unconfirmed_receipt_is_not_evidence(self):
        self.assertFalse(receipt(10, 1000).is_evidence)

    def test_confirmed_receipt_is_evidence(self):
        self.assertTrue(receipt(10, 1000, attested=1200).is_evidence)

    def test_malformed_receipts_are_rejected(self):
        for case, kwargs in {
            "negative size": {"size": -1, "claimed": 0},
            "negative attested": {"size": 1, "claimed": 0, "attested": -5},
        }.items():
            with self.subTest(case=case):
                with self.assertRaises(AnchorError):
                    receipt(**kwargs)

    def test_short_root_is_rejected(self):
        with self.assertRaises(AnchorError):
            AnchorReceipt(AnchorKind.RFC3161, 1, b"short", 0, b"x")


class TestBackdatingBound(unittest.TestCase):
    def test_an_anchor_covers_positions_below_its_size_only(self):
        # Size 10 covers positions 0..9. Position 10 was entered afterwards.
        anchors = [receipt(10, 1000, attested=1000)]
        self.assertIsNotNone(backdating_bound(anchors, 9))
        self.assertIsNone(backdating_bound(anchors, 10))
        self.assertIsNone(backdating_bound(anchors, 11))

    def test_boundary_is_exact_across_a_range(self):
        anchors = [receipt(size, 100 * size, attested=100 * size) for size in (5, 20, 50)]
        for position, expected_size in [
            (0, 5), (4, 5), (5, 20), (19, 20), (20, 50), (49, 50)
        ]:
            with self.subTest(position=position):
                bound = backdating_bound(anchors, position)
                self.assertEqual(bound.checkpoint_size, expected_size)
        self.assertIsNone(backdating_bound(anchors, 50))

    def test_the_earliest_attested_anchor_wins(self):
        anchors = [
            receipt(100, 5000, attested=5000),
            receipt(60, 2000, attested=2000),
            receipt(80, 3000, attested=3000),
        ]
        bound = backdating_bound(anchors, 10)
        self.assertEqual(bound.attested_at, 2000)

    def test_unconfirmed_anchors_cannot_bound_anything(self):
        anchors = [receipt(100, 1000), receipt(200, 2000)]
        self.assertIsNone(backdating_bound(anchors, 5))

    def test_unanchored_position_returns_none_rather_than_a_default(self):
        self.assertIsNone(backdating_bound([], 0))

    def test_negative_position_is_refused(self):
        with self.assertRaises(AnchorError):
            backdating_bound([receipt(5, 1, attested=1)], -1)

    def test_evidence_filter_excludes_unconfirmed(self):
        anchors = [receipt(10, 1, attested=1), receipt(20, 2)]
        self.assertEqual(len(evidence_only(anchors)), 1)


class TestStaleness(unittest.TestCase):
    def test_a_log_that_never_anchored_is_stale(self):
        # Otherwise a log that never anchored looks the same as one that does.
        self.assertTrue(is_stale([], now=10_000))

    def test_a_log_with_only_unconfirmed_anchors_is_stale(self):
        self.assertTrue(is_stale([receipt(10, 9_000)], now=10_000))

    def test_fresh_within_the_window(self):
        anchors = [receipt(10, 0, attested=10_000)]
        self.assertFalse(is_stale(anchors, now=10_000 + 3 * HOUR))

    def test_stale_past_the_window(self):
        anchors = [receipt(10, 0, attested=10_000)]
        self.assertTrue(is_stale(anchors, now=10_000 + 3 * HOUR + 1))

    def test_newest_anchor_decides(self):
        anchors = [receipt(10, 0, attested=0), receipt(20, 1, attested=10_000)]
        self.assertFalse(is_stale(anchors, now=10_000 + HOUR))

    def test_invalid_windows_are_refused(self):
        for interval, count in ((0, 3), (-1, 3), (HOUR, 0), (HOUR, -2)):
            with self.subTest(interval=interval, intervals=count):
                with self.assertRaises(AnchorError):
                    is_stale([], now=0, interval_seconds=interval, intervals=count)

    def test_latest_attested_ignores_unconfirmed(self):
        anchors = [receipt(10, 0, attested=500), receipt(20, 9_999)]
        self.assertEqual(latest_attested(anchors).attested_at, 500)
        self.assertIsNone(latest_attested([receipt(1, 1)]))


class TestSchedule(unittest.TestCase):
    def test_first_anchor_is_due_immediately(self):
        self.assertEqual(due_at([]), 0)

    def test_next_is_an_interval_after_the_last_submission(self):
        self.assertEqual(due_at([receipt(10, 5_000)]), 5_000 + HOUR)

    def test_an_unconfirmed_submission_still_counts_against_the_schedule(self):
        # Otherwise a slow confirmation causes the same window to be submitted
        # repeatedly.
        anchors = [receipt(10, 5_000, attested=5_100), receipt(20, 9_000)]
        self.assertEqual(due_at(anchors), 9_000 + HOUR)

    def test_invalid_interval_is_refused(self):
        with self.assertRaises(AnchorError):
            due_at([], interval_seconds=0)


class TestDivergence(unittest.TestCase):
    def roots(self, mapping):
        def root_at(size):
            if size not in mapping:
                raise KeyError(size)
            return mapping[size]

        return root_at

    def test_matching_roots_are_not_divergence(self):
        anchors = [receipt(10, 1, attested=1, root=ROOT_A)]
        self.assertEqual(diverged(anchors, self.roots({10: ROOT_A})), [])

    def test_a_changed_root_is_divergence(self):
        # The log published one history and holds another. This is the
        # split-view evidence the design exists to surface.
        anchors = [receipt(10, 1, attested=1, root=ROOT_A)]
        self.assertEqual(len(diverged(anchors, self.roots({10: ROOT_B}))), 1)

    def test_a_size_the_log_can_no_longer_produce_is_divergence(self):
        anchors = [receipt(99, 1, attested=1, root=ROOT_A)]
        self.assertEqual(len(diverged(anchors, self.roots({10: ROOT_A}))), 1)

    def test_unconfirmed_anchors_are_still_checked_for_divergence(self):
        # Confirmation governs whether a receipt can bound a time. It has
        # nothing to do with whether the root we published matches the log.
        anchors = [receipt(10, 1, root=ROOT_A)]
        self.assertEqual(len(diverged(anchors, self.roots({10: ROOT_B}))), 1)


class TestLedger(unittest.TestCase):
    def setUp(self):
        self.ledger = AnchorLedger()
        self.addCleanup(self.ledger.close)

    def test_receipts_round_trip(self):
        original = receipt(10, 1_000, attested=1_100)
        self.ledger.record(original)
        self.assertEqual(self.ledger.all(), [original])

    def test_receipts_cannot_be_deleted(self):
        self.ledger.record(receipt(10, 1_000))
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.ledger._connection.execute("DELETE FROM anchors")
        self.assertIn("append-only", str(caught.exception))

    def test_confirmation_attaches_an_attested_time(self):
        self.ledger.record(receipt(10, 1_000))
        self.ledger.confirm(receipt(10, 1_000, attested=1_500))
        self.assertEqual(self.ledger.all()[0].attested_at, 1_500)

    def test_an_attested_time_cannot_be_rewritten(self):
        # Otherwise the operator could move an anchor's time after the fact,
        # which is the backdating anchors exist to prevent.
        self.ledger.record(receipt(10, 1_000, attested=1_500))
        with self.assertRaises(AnchorError):
            self.ledger.confirm(receipt(10, 1_000, attested=900))
        self.assertEqual(self.ledger.all()[0].attested_at, 1_500)

    def test_the_database_refuses_to_rewrite_an_attested_time(self):
        # confirm() blocks this at the application level; the trigger is the
        # second barrier, for anything that reaches the table another way.
        # Moving an anchor's time after the fact is the backdating anchors
        # exist to prevent, so it is guarded twice on purpose.
        self.ledger.record(receipt(10, 1_000, attested=1_500))
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.ledger._connection.execute(
                "UPDATE anchors SET attested_at = 900 WHERE checkpoint_size = 10"
            )
        self.assertIn("once", str(caught.exception))
        self.assertEqual(self.ledger.all()[0].attested_at, 1_500)

    def test_the_anchored_root_cannot_be_changed_by_confirmation(self):
        self.ledger.record(receipt(10, 1_000, root=ROOT_A))
        with self.assertRaises(sqlite3.IntegrityError):
            self.ledger._connection.execute(
                "UPDATE anchors SET checkpoint_root = ? WHERE checkpoint_size = 10",
                (ROOT_B,),
            )

    def test_confirming_without_an_attested_time_is_refused(self):
        self.ledger.record(receipt(10, 1_000))
        with self.assertRaises(AnchorError):
            self.ledger.confirm(receipt(10, 1_000))

    def test_confirming_an_unknown_receipt_is_refused(self):
        with self.assertRaises(AnchorError):
            self.ledger.confirm(receipt(77, 1, attested=2))

    def test_receipts_are_returned_in_size_order(self):
        for size in (30, 10, 20):
            self.ledger.record(receipt(size, size))
        self.assertEqual([r.checkpoint_size for r in self.ledger.all()], [10, 20, 30])


class TestDirectoryAnchor(unittest.TestCase):
    def test_it_never_attests_a_time(self):
        # A file this process wrote proves only that this process wrote it, so a
        # development setup must not be able to look anchored.
        with tempfile.TemporaryDirectory() as directory:
            anchor = DirectoryAnchor(directory)
            written = anchor.submit(Checkpoint("example/log", 4, ROOT_A), now=1_000)
            self.assertIsNone(written.attested_at)
            self.assertFalse(written.is_evidence)
            self.assertIsNone(backdating_bound([written], 0))

    def test_it_writes_the_checkpoint_body(self):
        with tempfile.TemporaryDirectory() as directory:
            checkpoint = Checkpoint("example/log", 4, ROOT_A)
            DirectoryAnchor(directory).submit(checkpoint, now=1_000)
            written = (Path(directory) / "000000000004.checkpoint").read_bytes()
            self.assertEqual(written, checkpoint.body())

    def test_resubmitting_the_same_head_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            anchor = DirectoryAnchor(directory)
            checkpoint = Checkpoint("example/log", 4, ROOT_A)
            anchor.submit(checkpoint, now=1_000)
            anchor.submit(checkpoint, now=2_000)

    def test_a_second_head_at_the_same_size_is_refused(self):
        # Two different roots at one size is the fork itself.
        with tempfile.TemporaryDirectory() as directory:
            anchor = DirectoryAnchor(directory)
            anchor.submit(Checkpoint("example/log", 4, ROOT_A), now=1_000)
            with self.assertRaises(AnchorError) as caught:
                anchor.submit(Checkpoint("example/log", 4, ROOT_B), now=2_000)
            self.assertIn("diverged", str(caught.exception))

    def test_confirm_is_refused_rather_than_faked(self):
        with tempfile.TemporaryDirectory() as directory:
            anchor = DirectoryAnchor(directory)
            written = anchor.submit(Checkpoint("example/log", 1, ROOT_A), now=1)
            with self.assertRaises(AnchorError):
                anchor.confirm(written)


class TestAgainstARealLog(unittest.TestCase):
    def test_anchors_track_a_growing_log_and_catch_a_rewrite(self):
        from certifiles.log import TransparencyLog
        from certifiles.record import (
            AssuranceLevel,
            ClaimType,
            Content,
            Issuer,
            Record,
        )

        def make(i):
            return Record(
                Content(f"{i:064x}", "image/png", 100 + i),
                Issuer("opaque-identity-0001", AssuranceLevel.EMAIL, "k"),
                ClaimType.CREATED,
                1,
            )

        with TransparencyLog() as log:
            for i in range(8):
                log.append(make(i))
            anchored = AnchorReceipt(
                AnchorKind.RFC3161, 8, log.root(), 1_000, b"tok", attested_at=1_000
            )
            self.assertEqual(diverged([anchored], log.root), [])

            for i in range(8, 12):
                log.append(make(i))
            # Growth must not disturb an anchor over an earlier size.
            self.assertEqual(diverged([anchored], log.root), [])
            self.assertIsNotNone(backdating_bound([anchored], 7))
            self.assertIsNone(backdating_bound([anchored], 8))

        with TransparencyLog() as other:
            for i in range(7):
                other.append(make(i))
            other.append(make(99))  # a different eighth entry
            self.assertEqual(len(diverged([anchored], other.root)), 1)


if __name__ == "__main__":
    unittest.main()
