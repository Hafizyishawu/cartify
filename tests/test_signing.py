"""Ed25519 signing tests.

Skipped when `cryptography` is not installed, so the suite stays green in a
stdlib-only environment. These are the tests that prove a checkpoint Certifiles
produces is actually verifiable, so they must run before any checkpoint is
shown to a witness.
"""

import sys
import unittest

from certifiles.checkpoint import (
    Checkpoint,
    SignedCheckpoint,
    WitnessPolicy,
    add_signature,
    meets_quorum,
    parse,
    sign,
    verified_witnesses,
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
        self.log = InMemoryEd25519Signer.from_seed("example/log", b"\x09" * 32)
        self.policy = WitnessPolicy(
            version=1,
            effective_from_size=0,
            log_key_name="example/log",
            log_public_key=self.log.public_key,
            witnesses={
                "witness-a": self.signer.public_key,
                "witness-b": self.other.public_key,
            },
            required=2,
        )

    def test_public_key_is_32_raw_bytes(self):
        self.assertEqual(len(self.signer.public_key), 32)

    def test_signature_verifies(self):
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), self.signer))
        self.assertEqual(
            verified_witnesses(signed, self.policy, self.verifier), {"witness-a"}
        )

    def test_signature_survives_serialization(self):
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), self.signer))
        reparsed = parse(signed.serialize())
        self.assertEqual(
            verified_witnesses(reparsed, self.policy, self.verifier), {"witness-a"}
        )

    def test_two_witnesses_meet_quorum_of_two(self):
        signed = SignedCheckpoint(checkpoint())
        signed = add_signature(signed, sign(checkpoint(), self.log))
        signed = add_signature(signed, sign(checkpoint(), self.signer))
        signed = add_signature(signed, sign(checkpoint(), self.other))
        self.assertTrue(meets_quorum(signed, self.policy, self.verifier))

    def test_tampered_body_fails_verification(self):
        signature = sign(checkpoint(), self.signer)
        forged = SignedCheckpoint(checkpoint(size=813), (signature,))
        self.assertEqual(verified_witnesses(forged, self.policy, self.verifier), set())

    def test_tampered_root_fails_verification(self):
        signature = sign(checkpoint(), self.signer)
        forged = SignedCheckpoint(checkpoint(root_hash=bytes(32)), (signature,))
        self.assertEqual(verified_witnesses(forged, self.policy, self.verifier), set())

    def test_log_signature_does_not_count_as_a_witness(self):
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), self.log))
        self.assertEqual(verified_witnesses(signed, self.policy, self.verifier), frozenset())
        self.assertFalse(meets_quorum(signed, self.policy, self.verifier))

    def test_signature_from_wrong_key_fails(self):
        signature = sign(checkpoint(), self.other)
        mislabelled = SignedCheckpoint(checkpoint(), (signature,))
        self.assertEqual(
            verified_witnesses(mislabelled, self.policy, self.verifier), {"witness-b"}
        )
        self.assertNotIn("witness-a", verified_witnesses(mislabelled, self.policy, self.verifier))

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



class _BlockCryptography:
    """Makes `cryptography` unimportable inside the block.

    Clearing it from `sys.modules` is the load-bearing part. A meta_path finder
    alone does nothing once a module is already imported, which is always the
    case by the time this suite runs.
    """

    PREFIXES = ("cryptography", "certifiles")

    def find_spec(self, name, path=None, target=None):
        if name == "cryptography" or name.startswith("cryptography."):
            raise ImportError("cryptography is blocked for this test")
        return None

    def __enter__(self):
        self._saved = {
            name: module
            for name, module in sys.modules.items()
            if name.split(".")[0] in self.PREFIXES
        }
        for name in self._saved:
            del sys.modules[name]
        sys.meta_path.insert(0, self)
        return self

    def __exit__(self, *_exc):
        sys.meta_path.remove(self)
        for name in [n for n in sys.modules if n.split(".")[0] in self.PREFIXES]:
            del sys.modules[name]
        sys.modules.update(self._saved)
        return False


class TestLazyDependency(unittest.TestCase):
    """`cryptography` must stay optional for everything except signing.

    The package parses and builds checkpoints with only the standard library,
    which is what lets a verifier run somewhere that installs nothing. CI
    installs cryptography, so this test is the only thing standing between that
    contract and a top-level import added to an unrelated module.
    """

    def test_every_module_imports_without_cryptography(self):
        import importlib
        import pkgutil

        import certifiles

        names = [
            f"certifiles.{module.name}"
            for module in pkgutil.iter_modules(certifiles.__path__)
        ]
        self.assertGreater(len(names), 10, "module discovery found almost nothing")

        with _BlockCryptography():
            for name in names:
                with self.subTest(module=name):
                    importlib.import_module(name)

    def test_the_blocker_actually_blocks(self):
        # Without this, the test above passes for the wrong reason and would
        # keep passing after the contract it guards had been broken.
        with _BlockCryptography():
            import certifiles.checkpoint as checkpoint
            import certifiles.signing as signing

            # Resolved through the freshly imported modules: the block clears
            # certifiles from sys.modules, so the class raised inside is not the
            # same object as the one this file imported at the top.
            with self.assertRaises(checkpoint.CheckpointError) as caught:
                signing.InMemoryEd25519Signer.from_seed("origin", b"\x01" * 32)
            self.assertIn("cryptography", str(caught.exception))
