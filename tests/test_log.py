"""Transparency log storage tests.

The properties under test are the ones an ownership dispute turns on: positions
are gapless and permanent, history cannot be rewritten through this code, and
every proof the log issues verifies against the root it also issues.
"""

import sqlite3
import unittest

from certifiles.checkpoint import CheckpointError
from certifiles.log import LogError, TransparencyLog
from certifiles.merkle import verify_consistency, verify_inclusion
from certifiles.record import (
    AssuranceLevel,
    ClaimType,
    Content,
    Issuer,
    Record,
    RecordError,
)


def record(seed: int = 0, identity: str = "opaque-identity-0001", **overrides) -> Record:
    fields = {
        "content": Content(
            sha256=f"{seed:064x}", media_type="image/png", size_bytes=1000 + seed
        ),
        "issuer": Issuer(identity, AssuranceLevel.EMAIL, "key-2026-09"),
        "claim_type": ClaimType.CREATED,
        "policy_version": 1,
    }
    fields.update(overrides)
    return Record(**fields)


class _FailsOnInsert:
    """Connection proxy that fails the INSERT so the rollback path is reached.

    sqlite3.Connection.execute cannot be reassigned, hence a proxy.
    """

    def __init__(self, real):
        self._real = real

    def execute(self, sql, *args):
        if sql.lstrip().upper().startswith("INSERT"):
            raise sqlite3.OperationalError("simulated write failure")
        return self._real.execute(sql, *args)

    def __getattr__(self, name):
        return getattr(self._real, name)


class LogTestCase(unittest.TestCase):
    def setUp(self):
        self.log = TransparencyLog()
        self.addCleanup(self.log.close)


class TestAppend(LogTestCase):
    def test_empty_log(self):
        self.assertEqual(self.log.size(), 0)
        self.assertEqual(self.log.entry(0), None)

    def test_positions_start_at_zero_and_are_gapless(self):
        positions = [self.log.append(record(i)).position for i in range(25)]
        self.assertEqual(positions, list(range(25)))
        self.assertEqual(self.log.size(), 25)

    def test_entry_round_trips(self):
        appended = self.log.append(record(7))
        stored = self.log.entry(appended.position)
        self.assertEqual(stored, appended)

    def test_invalid_record_never_reaches_the_log(self):
        bad = record(1, content=Content("NOT A HASH", "image/png", 10))
        with self.assertRaises(RecordError):
            self.log.append(bad)
        self.assertEqual(self.log.size(), 0)

    def test_leaf_hash_matches_the_record(self):
        entry = self.log.append(record(3))
        self.assertEqual(entry.leaf_data, record(3).leaf_data())


class TestAppendOnly(LogTestCase):
    """History cannot be rewritten through this code path."""

    def test_update_is_refused_by_the_database(self):
        self.log.append(record(1))
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.log._connection.execute(
                "UPDATE records SET content_hash = 'x' WHERE position = 0"
            )
        self.assertIn("append-only", str(caught.exception))

    def test_delete_is_refused_by_the_database(self):
        self.log.append(record(1))
        with self.assertRaises(sqlite3.IntegrityError) as caught:
            self.log._connection.execute("DELETE FROM records WHERE position = 0")
        self.assertIn("append-only", str(caught.exception))

    def test_position_cannot_be_reused(self):
        self.log.append(record(1))
        with self.assertRaises(sqlite3.IntegrityError):
            self.log._connection.execute(
                "INSERT INTO records (position, leaf_hash, leaf_data, content_hash,"
                " identity_id) VALUES (0, x'00', x'00', 'a', 'b')"
            )

    def test_a_failure_inside_the_transaction_rolls_back(self):
        # The earlier gap test fails at validation, before a transaction opens,
        # so it never exercises the rollback. Forcing the INSERT to fail does.
        # Without the rollback the connection is left mid-transaction and the
        # next append dies on "cannot start a transaction within a transaction".
        self.log.append(record(1))
        real = self.log._connection
        self.log._connection = _FailsOnInsert(real)
        try:
            with self.assertRaises(sqlite3.OperationalError):
                self.log.append(record(2))
        finally:
            self.log._connection = real

        self.assertEqual(self.log.size(), 1)
        self.assertEqual(self.log.append(record(3)).position, 1)

    def test_concurrent_appends_never_collide_on_a_position(self):
        # BEGIN IMMEDIATE takes the write lock before the size is read. Without
        # it two writers compute the same position and one silently loses.
        import os
        import tempfile
        import threading

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "concurrent.db")
            TransparencyLog(path).close()
            positions, errors = [], []
            lock = threading.Lock()

            def worker(worker_id):
                try:
                    log = TransparencyLog(path)
                    log._connection.execute("PRAGMA busy_timeout=5000")
                    for i in range(8):
                        entry = log.append(record(worker_id * 100 + i))
                        with lock:
                            positions.append(entry.position)
                    log.close()
                except Exception as exc:  # recorded, asserted below
                    with lock:
                        errors.append(repr(exc))

            threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

            self.assertEqual(errors, [])
            self.assertEqual(len(positions), 48)
            self.assertEqual(sorted(positions), list(range(48)))

    def test_one_connection_shared_across_threads_stays_gapless(self):
        # The HTTP service handles each request in its own thread against a
        # single store. Statement-level serialisation does not make the
        # read-size-then-insert sequence atomic, so append holds a lock; without
        # it two threads compute the same position.
        import threading

        positions, errors = [], []
        lock = threading.Lock()

        def worker(worker_id):
            try:
                for i in range(10):
                    entry = self.log.append(record(worker_id * 100 + i))
                    with lock:
                        positions.append(entry.position)
            except Exception as exc:
                with lock:
                    errors.append(repr(exc))

        threads = [threading.Thread(target=worker, args=(n,)) for n in range(6)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        self.assertEqual(errors, [])
        self.assertEqual(sorted(positions), list(range(60)))
        self.log.check_integrity()

    def test_a_failed_append_leaves_no_gap(self):
        self.log.append(record(1))
        with self.assertRaises(RecordError):
            self.log.append(record(2, content=Content("bad", "image/png", 1)))
        self.assertEqual(self.log.append(record(3)).position, 1)
        self.assertEqual(self.log.size(), 2)


class TestDuplicateClaims(LogTestCase):
    """Duplicates are accepted; priority is expressed by position."""

    def test_the_same_fingerprint_can_be_claimed_twice(self):
        first = self.log.append(record(5, identity="opaque-identity-0001"))
        second = self.log.append(record(5, identity="opaque-identity-0002"))
        self.assertEqual((first.position, second.position), (0, 1))

    def test_claims_are_returned_earliest_first(self):
        self.log.append(record(9, identity="opaque-identity-first"))
        self.log.append(record(1))
        self.log.append(record(9, identity="opaque-identity-later"))
        claims = self.log.claims_for(f"{9:064x}")
        self.assertEqual([c.position for c in claims], [0, 2])
        self.assertEqual(claims[0].identity_id, "opaque-identity-first")

    def test_unknown_fingerprint_returns_nothing_rather_than_raising(self):
        self.assertEqual(self.log.claims_for("f" * 64), [])

    def test_claims_by_identity(self):
        self.log.append(record(1, identity="opaque-identity-aaaa"))
        self.log.append(record(2, identity="opaque-identity-bbbb"))
        self.log.append(record(3, identity="opaque-identity-aaaa"))
        self.assertEqual(
            [c.position for c in self.log.claims_by("opaque-identity-aaaa")], [0, 2]
        )


class TestProofs(LogTestCase):
    def test_every_inclusion_proof_verifies_against_the_logs_own_root(self):
        for i in range(24):
            self.log.append(record(i))
        size = self.log.size()
        root = self.log.root()
        for position in range(size):
            with self.subTest(position=position):
                proof = self.log.inclusion_proof(position)
                entry = self.log.entry(position)
                self.assertTrue(
                    verify_inclusion(entry.leaf_hash, position, size, proof, root)
                )

    def test_every_growth_step_produces_a_verifying_consistency_proof(self):
        for i in range(20):
            self.log.append(record(i))
        size = self.log.size()
        new_root = self.log.root()
        for old_size in range(1, size + 1):
            with self.subTest(old_size=old_size):
                proof = self.log.consistency_proof(old_size)
                self.assertTrue(
                    verify_consistency(
                        old_size, size, proof, self.log.root(old_size), new_root
                    )
                )

    def test_historical_roots_stay_stable_as_the_log_grows(self):
        # If a past root changed on append, every proof already issued against
        # it would break, and the log would be indistinguishable from one that
        # had rewritten history.
        for i in range(10):
            self.log.append(record(i))
        snapshot = {n: self.log.root(n) for n in range(11)}
        for i in range(10, 20):
            self.log.append(record(i))
        for n, root in snapshot.items():
            with self.subTest(size=n):
                self.assertEqual(self.log.root(n), root)

    def test_proof_for_a_position_outside_the_tree_is_refused(self):
        self.log.append(record(1))
        for bad in (-1, 1, 99):
            with self.subTest(position=bad):
                with self.assertRaises(LogError):
                    self.log.inclusion_proof(bad)

    def test_consistency_proof_bounds_are_enforced(self):
        for i in range(4):
            self.log.append(record(i))
        for bad in (0, 5, -1):
            with self.subTest(old_size=bad):
                with self.assertRaises(LogError):
                    self.log.consistency_proof(bad)

    def test_root_of_a_size_beyond_the_log_is_refused(self):
        self.log.append(record(1))
        with self.assertRaises(LogError):
            self.log.root(2)


class TestCheckpoints(LogTestCase):
    def test_checkpoint_reflects_current_size_and_root(self):
        for i in range(6):
            self.log.append(record(i))
        checkpoint = self.log.checkpoint("certifiles.example/log")
        self.assertEqual(checkpoint.size, 6)
        self.assertEqual(checkpoint.root_hash, self.log.root())
        self.assertEqual(checkpoint.origin, "certifiles.example/log")

    def test_checkpoint_for_a_historical_size(self):
        for i in range(6):
            self.log.append(record(i))
        checkpoint = self.log.checkpoint("certifiles.example/log", size=3)
        self.assertEqual(checkpoint.size, 3)
        self.assertEqual(checkpoint.root_hash, self.log.root(3))

    def test_empty_log_checkpoint_is_representable(self):
        checkpoint = self.log.checkpoint("certifiles.example/log")
        self.assertEqual(checkpoint.size, 0)

    def test_checkpoint_rejects_a_malformed_origin(self):
        with self.assertRaises(CheckpointError):
            self.log.checkpoint("")

    def test_the_log_holds_no_signing_key(self):
        # Signing lives behind the signer boundary so a production signer can
        # call a KMS that never releases key material.
        surface = [n for n in dir(self.log) if not n.startswith("_")]
        self.assertNotIn("sign", surface)
        self.assertFalse([n for n in surface if "key" in n.lower()])


class TestTamperDetection(unittest.TestCase):
    """A forged gap must fail loudly, never produce a plausible wrong proof."""

    def _log_with_forged_gap(self, directory):
        import os

        path = os.path.join(directory, "gapped.db")
        with TransparencyLog(path) as log:
            for i in range(6):
                log.append(record(i))
            honest_root = log.root()
        raw = sqlite3.connect(path)
        raw.executescript(
            "DROP TRIGGER records_are_append_only_delete;"
            "DELETE FROM records WHERE position = 2;"
        )
        raw.commit()
        raw.close()
        return path, honest_root

    def test_opening_a_gapped_log_is_refused(self):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path, _ = self._log_with_forged_gap(directory)
            with self.assertRaises(LogError) as caught:
                TransparencyLog(path)
            self.assertIn("not contiguous", str(caught.exception))
            # __init__ raised after connecting, so nothing closed the handle.
            import gc

            gc.collect()

    def test_a_gapped_log_never_serves_a_proof(self):
        # The failure that matters: every leaf after a gap shifts, so proofs
        # would verify against a root no honest history could produce.
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path, honest_root = self._log_with_forged_gap(directory)
            try:
                log = TransparencyLog(path)
            except LogError:
                import gc

                gc.collect()
                return  # refused at the door, which is the stronger outcome
            self.addCleanup(log.close)
            for call in (log.root, lambda: log.inclusion_proof(0), log.size):
                with self.assertRaises(LogError):
                    call()

    def test_a_gap_opened_under_a_live_log_is_caught_before_any_proof(self):
        # check_integrity guards the door; this guards the room. A log already
        # open when the gap appears never reaches check_integrity again, so the
        # leaf-count guard is what stands between it and a wrong root.
        with TransparencyLog() as log:
            for i in range(6):
                log.append(record(i))
            log._connection.executescript(
                "DROP TRIGGER records_are_append_only_delete;"
                "DELETE FROM records WHERE position = 2;"
            )
            with self.assertRaises(LogError):
                log.root()
            with self.assertRaises(LogError):
                log.inclusion_proof(0)

    def test_check_integrity_passes_on_an_honest_log(self):
        with TransparencyLog() as log:
            for i in range(5):
                log.append(record(i))
            log.check_integrity()


class TestPersistence(unittest.TestCase):
    def test_a_log_survives_reopening(self):
        import tempfile, os

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "log.db")
            with TransparencyLog(path) as log:
                for i in range(5):
                    log.append(record(i))
                root, size = log.root(), log.size()
            with TransparencyLog(path) as reopened:
                self.assertEqual(reopened.size(), size)
                self.assertEqual(reopened.root(), root)
                self.assertEqual(reopened.append(record(99)).position, 5)


if __name__ == "__main__":
    unittest.main()
