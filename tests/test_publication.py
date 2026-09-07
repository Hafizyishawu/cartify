"""Static publication tests.

The property that matters: a verifier holding only these files, with no access
to the service, can prove a record is in the log — and cannot be fooled by a
published tree that disagrees with itself.
"""

import json
import tempfile
import unittest
from pathlib import Path

from certifiles.anchoring import AnchorKind, AnchorReceipt
from certifiles.checkpoint import Checkpoint, SignedCheckpoint
from certifiles.log import TransparencyLog
from certifiles.merkle import verify_consistency, verify_inclusion
from certifiles.publication import (
    FORMAT_VERSION,
    PublicationError,
    PublishReport,
    StaticPublication,
)
from certifiles.record import (
    AssuranceLevel,
    ClaimType,
    Content,
    Issuer,
    Record,
)

ORIGIN = "certifiles.example/log"


def make_record(i: int, identity: str = "opaque-identity-0001") -> Record:
    return Record(
        Content(f"{i:064x}", "image/png", 100 + i),
        Issuer(identity, AssuranceLevel.EMAIL, "key-2026-09"),
        ClaimType.CREATED,
        1,
    )


class PublicationTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.site = StaticPublication(self.root)
        self.log = TransparencyLog()
        self.addCleanup(self.log.close)

    def fill(self, count: int) -> None:
        for i in range(count):
            self.log.append(make_record(i))

    def head(self, size: int | None = None) -> SignedCheckpoint:
        return SignedCheckpoint(self.log.checkpoint(ORIGIN, size=size))


class TestLayout(PublicationTestCase):
    def test_publishes_the_expected_files(self):
        self.fill(3)
        self.site.publish(self.log, self.head())
        for expected in (
            "manifest.json",
            "checkpoint",
            "checkpoints/000000000003",
            "entries/0000/0000/0000.json",
            "entries/0000/0000/0002.json",
            "proofs/inclusion/0000/0000/0001.json",
        ):
            with self.subTest(path=expected):
                self.assertTrue((self.root / expected).exists(), expected)

    def test_positions_are_sharded_three_levels_deep(self):
        self.fill(1)
        self.site.publish(self.log, self.head())
        self.assertTrue((self.root / "entries/0000/0000/0000.json").exists())

    def test_content_index_is_sharded_by_hash_prefix(self):
        self.fill(1)
        self.site.publish(self.log, self.head())
        digest = f"{0:064x}"
        expected = self.root / f"index/by-content/{digest[:2]}/{digest[2:4]}/{digest}.json"
        self.assertTrue(expected.exists())

    def test_manifest_declares_the_format_version(self):
        self.fill(2)
        self.site.publish(self.log, self.head())
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.assertEqual(manifest["format_version"], FORMAT_VERSION)
        self.assertEqual(manifest["size"], 2)
        self.assertEqual(manifest["root_hash"], self.log.root().hex())

    def test_manifest_says_the_index_is_not_evidence(self):
        self.fill(1)
        self.site.publish(self.log, self.head())
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.assertIn("not evidence", manifest["notice"])


class TestOfflineVerification(PublicationTestCase):
    """A verifier with the files and nothing else."""

    def test_every_published_record_verifies_from_files_alone(self):
        self.fill(17)
        signed = self.head()
        self.site.publish(self.log, signed)

        published_root = signed.checkpoint.root_hash
        for position in range(17):
            with self.subTest(position=position):
                entry = self.site.entry(position)
                proof = self.site.inclusion_proof(position)
                self.assertTrue(
                    verify_inclusion(
                        bytes.fromhex(entry["leaf_hash"]),
                        proof["position"],
                        proof["tree_size"],
                        [bytes.fromhex(n) for n in proof["proof"]],
                        published_root,
                    )
                )

    def test_the_published_leaf_hash_matches_the_published_leaf(self):
        # Otherwise a verifier could be handed a leaf hash that does not belong
        # to the record shown beside it.
        from certifiles.merkle import leaf_hash

        self.fill(4)
        self.site.publish(self.log, self.head())
        for position in range(4):
            entry = self.site.entry(position)
            with self.subTest(position=position):
                self.assertEqual(
                    leaf_hash(entry["leaf"].encode("utf-8")).hex(), entry["leaf_hash"]
                )

    def test_lookup_by_fingerprint_finds_every_claim(self):
        self.log.append(make_record(7, identity="opaque-identity-first"))
        self.log.append(make_record(1))
        self.log.append(make_record(7, identity="opaque-identity-later"))
        self.site.publish(self.log, self.head())
        self.assertEqual(self.site.positions_for(f"{7:064x}"), [0, 2])

    def test_unknown_fingerprint_returns_nothing(self):
        self.fill(2)
        self.site.publish(self.log, self.head())
        self.assertEqual(self.site.positions_for("f" * 64), [])

    def test_proofs_are_relative_to_the_published_head_not_the_live_log(self):
        # Publishing a head behind the live log is the case that separates
        # them: a proof against the current size would not verify against the
        # root actually published, and every earlier test happened to publish
        # at the live size.
        self.fill(12)
        historical = self.head(size=5)
        self.site.publish(self.log, historical)
        for position in range(5):
            proof = self.site.inclusion_proof(position)
            entry = self.site.entry(position)
            with self.subTest(position=position):
                self.assertEqual(proof["tree_size"], 5)
                self.assertTrue(
                    verify_inclusion(
                        bytes.fromhex(entry["leaf_hash"]),
                        position,
                        5,
                        [bytes.fromhex(n) for n in proof["proof"]],
                        historical.checkpoint.root_hash,
                    )
                )

    def test_consistency_proofs_chain_an_old_head_to_a_new_one(self):
        self.fill(6)
        first = self.head()
        self.site.publish(self.log, first)
        self.fill(6)
        second = self.head()
        self.site.publish(self.log, second, previous_sizes=[6])

        published = json.loads(
            (self.root / "proofs/consistency/000000000006-000000000012.json").read_text()
        )
        self.assertTrue(
            verify_consistency(
                published["from_size"],
                published["to_size"],
                [bytes.fromhex(n) for n in published["proof"]],
                first.checkpoint.root_hash,
                second.checkpoint.root_hash,
            )
        )


class TestImmutability(PublicationTestCase):
    def test_republishing_unchanged_data_is_a_no_op(self):
        self.fill(5)
        signed = self.head()
        self.site.publish(self.log, signed)
        second = self.site.publish(self.log, signed)
        self.assertEqual(second.written, [])
        self.assertGreater(len(second.unchanged), 0)

    def test_growth_leaves_earlier_entries_untouched(self):
        self.fill(4)
        self.site.publish(self.log, self.head())
        original = (self.root / "entries/0000/0000/0000.json").read_bytes()
        original_proof = (self.root / "proofs/inclusion/0000/0000/0000.json").read_bytes()
        self.fill(4)
        self.site.publish(self.log, self.head())
        self.assertEqual((self.root / "entries/0000/0000/0000.json").read_bytes(), original)
        self.assertEqual(
            (self.root / "proofs/inclusion/0000/0000/0000.json").read_bytes(),
            original_proof,
        )

    def test_rewriting_a_published_entry_is_refused(self):
        # A published entry that changes is either a bug or a rewrite of
        # history. Both should stop the run rather than succeed quietly.
        self.fill(2)
        self.site.publish(self.log, self.head())
        (self.root / "entries/0000/0000/0000.json").write_text('{"position":0}')
        with self.assertRaises(PublicationError) as caught:
            self.site.publish(self.log, self.head())
        self.assertIn("not rewritten", str(caught.exception))

    def test_rewriting_a_published_checkpoint_is_refused(self):
        self.fill(3)
        self.site.publish(self.log, self.head())
        (self.root / "checkpoints/000000000003").write_bytes(b"forged\n")
        with self.assertRaises(PublicationError):
            self.site.publish(self.log, self.head())

    def test_the_latest_pointer_is_allowed_to_move(self):
        self.fill(2)
        self.site.publish(self.log, self.head())
        first = self.site.latest_checkpoint()
        self.fill(2)
        self.site.publish(self.log, self.head())
        self.assertNotEqual(self.site.latest_checkpoint(), first)


class TestAuditRegressions(PublicationTestCase):
    """Every one of these reproduces a defect found by adversarial audit."""

    def signed(self, size=None, *names):
        import hashlib

        from certifiles.checkpoint import Signature, add_signature, key_hash, sign

        class Stub:
            def __init__(self, name):
                self.key_name = name
                self.public_key = name.encode().ljust(32, b"\x00")

            def sign(self, message):
                return hashlib.sha512(self.public_key + message).digest()[:64]

        result = SignedCheckpoint(self.log.checkpoint(ORIGIN, size=size))
        for name in names:
            result = add_signature(result, sign(result.checkpoint, Stub(name)))
        return result

    def test_a_witness_cosignature_can_be_added_to_a_published_head(self):
        # ADR 0001 issues records PENDING_WITNESS and raises their assurance
        # when a witnessed head covers them. Treating the serialized bytes as
        # immutable made that lifecycle structurally unreachable.
        self.fill(3)
        pending = self.signed(None, "certifiles.example/log")
        self.site.publish(self.log, pending)
        witnessed = self.signed(None, "certifiles.example/log", "witness-a")
        self.site.publish(self.log, witnessed)
        from certifiles.checkpoint import parse

        republished = parse((self.root / "checkpoints/000000000003").read_bytes())
        self.assertEqual(len(republished.signatures), 2)

    def test_a_different_tree_head_at_a_published_size_is_still_refused(self):
        # The body is what must never change; that is the split view.
        self.fill(3)
        self.site.publish(self.log, self.signed())
        forged = SignedCheckpoint(Checkpoint(ORIGIN, 3, bytes(32)))
        with self.assertRaises(PublicationError):
            self.site._publish_checkpoint(PublishReport(), forged)

    def test_dropping_an_already_published_signature_is_refused(self):
        # Assurance is never revised downward silently.
        self.fill(3)
        self.site.publish(self.log, self.signed(None, "log-key", "witness-a"))
        with self.assertRaises(PublicationError) as caught:
            self.site.publish(self.log, self.signed(None, "log-key"))
        self.assertIn("lose", str(caught.exception))

    def test_an_anchor_the_log_cannot_support_is_refused(self):
        from certifiles.anchoring import AnchorKind, AnchorReceipt

        self.fill(4)
        bogus = AnchorReceipt(AnchorKind.RFC3161, 4, b"\xde\xad" * 16, 1, b"x", 1)
        with self.assertRaises(PublicationError) as caught:
            self.site.publish(self.log, self.signed(), anchors=[bogus])
        self.assertIn("divergence", str(caught.exception))

    def test_an_attested_anchor_time_cannot_be_moved_by_republishing(self):
        # Rewriting this file was a way to move a backdating bound earlier.
        from certifiles.anchoring import AnchorKind, AnchorReceipt

        self.fill(4)
        honest = AnchorReceipt(AnchorKind.RFC3161, 4, self.log.root(4), 1, b"t", 5_100)
        self.site.publish(self.log, self.signed(), anchors=[honest])
        earlier = AnchorReceipt(AnchorKind.RFC3161, 4, self.log.root(4), 1, b"t", 1)
        with self.assertRaises(PublicationError) as caught:
            self.site.publish(self.log, self.signed(), anchors=[earlier])
        self.assertIn("set once", str(caught.exception))

    def test_a_confirmation_may_still_be_added_to_an_unconfirmed_anchor(self):
        from certifiles.anchoring import AnchorKind, AnchorReceipt

        self.fill(4)
        pending = AnchorReceipt(AnchorKind.RFC3161, 4, self.log.root(4), 1, b"t", None)
        self.site.publish(self.log, self.signed(), anchors=[pending])
        confirmed = AnchorReceipt(AnchorKind.RFC3161, 4, self.log.root(4), 1, b"t", 5_000)
        self.site.publish(self.log, self.signed(), anchors=[confirmed])
        published = json.loads((self.root / "anchors/000000000004.json").read_text())
        self.assertEqual(published["anchors"][0]["attested_at"], 5_000)

    def test_the_published_head_cannot_move_backwards(self):
        # Entries and proofs for the newer head stay on disk, so rewinding the
        # entry point advertises a head a witness may already have passed.
        self.fill(6)
        self.site.publish(self.log, self.signed())
        with self.assertRaises(PublicationError) as caught:
            self.site.publish(self.log, self.signed(size=3))
        self.assertIn("backwards", str(caught.exception))

    def test_a_content_hash_cannot_escape_the_publication_root(self):
        # Becomes remote arbitrary-file read the moment a verify endpoint
        # passes a user-supplied hash through here.
        for bad in ("../../../../stolen", "aa/bb", "AA" * 32, "zz" * 32, "abc"):
            with self.subTest(value=bad):
                with self.assertRaises(PublicationError):
                    self.site.positions_for(bad)

    def test_a_corrupt_published_index_raises_a_publication_error(self):
        self.fill(2)
        self.site.publish(self.log, self.signed())
        digest = f"{0:064x}"
        (self.root / f"index/by-content/{digest[:2]}/{digest[2:4]}/{digest}.json").write_text("{")
        with self.assertRaises(PublicationError):
            self.site.positions_for(digest)
        with self.assertRaises(PublicationError):
            self.site.publish(self.log, self.signed())


class TestRefusals(PublicationTestCase):
    def test_a_checkpoint_larger_than_the_log_is_refused(self):
        self.fill(2)
        oversized = SignedCheckpoint(Checkpoint(ORIGIN, 9, self.log.root(2)))
        with self.assertRaises(PublicationError):
            self.site.publish(self.log, oversized)

    def test_a_checkpoint_whose_root_the_log_cannot_support_is_refused(self):
        # Publishing a head the log does not produce is exactly the split view
        # the design exists to prevent, so it stops here too.
        self.fill(4)
        forged = SignedCheckpoint(Checkpoint(ORIGIN, 4, bytes(32)))
        with self.assertRaises(PublicationError) as caught:
            self.site.publish(self.log, forged)
        self.assertIn("does not match", str(caught.exception))

    def test_publishing_an_empty_log_is_allowed(self):
        report = self.site.publish(self.log, self.head())
        self.assertEqual(report.size, 0)
        self.assertTrue((self.root / "manifest.json").exists())

    def test_negative_position_shard_is_refused(self):
        from certifiles.publication import _sharded

        with self.assertRaises(PublicationError):
            _sharded(-1)


class TestAnchorPublication(PublicationTestCase):
    def anchor(self, size, attested=None):
        return AnchorReceipt(
            AnchorKind.RFC3161, size, self.log.root(size), 1_000, b"tok", attested
        )

    def test_anchors_are_published_per_checkpoint_size(self):
        self.fill(5)
        self.site.publish(self.log, self.head(), anchors=[self.anchor(5, attested=2_000)])
        published = json.loads((self.root / "anchors/000000000005.json").read_text())
        self.assertEqual(published["anchors"][0]["attested_at"], 2_000)

    def test_an_unconfirmed_anchor_publishes_a_null_attested_time(self):
        # A verifier must be able to tell "not yet confirmed" from "confirmed
        # at some time", so the absence is explicit rather than omitted.
        self.fill(5)
        self.site.publish(self.log, self.head(), anchors=[self.anchor(5)])
        published = json.loads((self.root / "anchors/000000000005.json").read_text())
        self.assertIsNone(published["anchors"][0]["attested_at"])

    def test_manifest_reports_the_latest_attested_anchor(self):
        self.fill(5)
        self.site.publish(
            self.log,
            self.head(),
            anchors=[self.anchor(5, attested=2_000), self.anchor(5, attested=9_000)],
        )
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.assertEqual(manifest["latest_attested_anchor"], 9_000)

    def test_manifest_reports_no_anchor_when_there_is_none(self):
        self.fill(2)
        self.site.publish(self.log, self.head())
        manifest = json.loads((self.root / "manifest.json").read_text())
        self.assertIsNone(manifest["latest_attested_anchor"])

    def test_a_confirmed_anchor_may_replace_an_unconfirmed_one(self):
        # OpenTimestamps upgrades a receipt when its transaction confirms.
        self.fill(3)
        self.site.publish(self.log, self.head(), anchors=[self.anchor(3)])
        self.site.publish(self.log, self.head(), anchors=[self.anchor(3, attested=5_000)])
        published = json.loads((self.root / "anchors/000000000003.json").read_text())
        self.assertEqual(published["anchors"][0]["attested_at"], 5_000)


if __name__ == "__main__":
    unittest.main()
