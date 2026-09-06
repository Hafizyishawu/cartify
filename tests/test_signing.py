"""Ed25519 signing tests.

Skipped when `cryptography` is not installed, so the suite stays green in a
stdlib-only environment. These are the tests that prove a checkpoint Certifiles
produces is actually verifiable, so they must run before any checkpoint is
shown to a witness.
"""

import unittest

from certifiles.checkpoint import (
    Checkpoint,
    SignedCheckpoint,
    add_signature,
    meets_quorum,
    parse,
    sign,
    verified_signers,
)

try:
    import cryptography  # noqa: F401

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False

if HAS_CRYPTOGRAPHY:
    from certifiles.signing import Ed25519Verifier, InMemoryEd25519Signer

ORIGIN = "certifiles.com/log/2026"
ROOT = bytes(range(32))


def checkpoint(**overrides) -> Checkpoint:
    fields = {"origin": ORIGIN, "size": 812, "root_hash": ROOT}
    fields.update(overrides)
    return Checkpoint(**fields)


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "requires the cryptography package")
class TestEd25519(unittest.TestCase):
    def setUp(self):
        self.signer = InMemoryEd25519Signer.from_seed("witness-a", b"\x01" * 32)
        self.other = InMemoryEd25519Signer.from_seed("witness-b", b"\x02" * 32)
        self.verifier = Ed25519Verifier()
        self.keys = {
            "witness-a": self.signer.public_key,
            "witness-b": self.other.public_key,
        }

    def test_public_key_is_32_raw_bytes(self):
        self.assertEqual(len(self.signer.public_key), 32)

    def test_signature_verifies(self):
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), self.signer))
        self.assertEqual(
            verified_signers(signed, self.keys, self.verifier), {"witness-a"}
        )

    def test_signature_survives_serialization(self):
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), self.signer))
        reparsed = parse(signed.serialize())
        self.assertEqual(
            verified_signers(reparsed, self.keys, self.verifier), {"witness-a"}
        )

    def test_two_witnesses_meet_quorum_of_two(self):
        signed = SignedCheckpoint(checkpoint())
        signed = add_signature(signed, sign(checkpoint(), self.signer))
        signed = add_signature(signed, sign(checkpoint(), self.other))
        self.assertTrue(meets_quorum(signed, self.keys, self.verifier, 2))

    def test_tampered_body_fails_verification(self):
        signature = sign(checkpoint(), self.signer)
        forged = SignedCheckpoint(checkpoint(size=813), (signature,))
        self.assertEqual(verified_signers(forged, self.keys, self.verifier), set())

    def test_tampered_root_fails_verification(self):
        signature = sign(checkpoint(), self.signer)
        forged = SignedCheckpoint(checkpoint(root_hash=bytes(32)), (signature,))
        self.assertEqual(verified_signers(forged, self.keys, self.verifier), set())

    def test_signature_from_wrong_key_fails(self):
        signature = sign(checkpoint(), self.other)
        mislabelled = SignedCheckpoint(checkpoint(), (signature,))
        self.assertEqual(
            verified_signers(mislabelled, self.keys, self.verifier), {"witness-b"}
        )
        self.assertNotIn("witness-a", verified_signers(mislabelled, self.keys, self.verifier))

    def test_seed_determines_key(self):
        again = InMemoryEd25519Signer.from_seed("witness-a", b"\x01" * 32)
        self.assertEqual(again.public_key, self.signer.public_key)

    def test_generate_produces_distinct_keys(self):
        a = InMemoryEd25519Signer.generate("w")
        b = InMemoryEd25519Signer.generate("w")
        self.assertNotEqual(a.public_key, b.public_key)

    def test_bad_seed_length_is_rejected(self):
        from certifiles.checkpoint import CheckpointError

        with self.assertRaises(CheckpointError):
            InMemoryEd25519Signer.from_seed("w", b"\x01" * 31)

    def test_verifier_rejects_malformed_public_key(self):
        self.assertFalse(self.verifier.verify(b"short", b"msg", b"\x00" * 64))

    def test_verifier_rejects_wrong_length_signature(self):
        self.assertFalse(self.verifier.verify(self.signer.public_key, b"msg", b"\x00" * 63))

    def test_no_load_from_file_convenience_exists(self):
        # A development key must not have an easy path into production use.
        self.assertFalse(
            any(
                name.startswith(("from_file", "load"))
                for name in dir(InMemoryEd25519Signer)
            )
        )


if __name__ == "__main__":
    unittest.main()
