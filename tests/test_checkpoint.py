"""Checkpoint format tests.

No cryptography dependency: signature verification is injected, so the parts
that carry security weight here — strict parsing and distinct-witness
counting — are exercised without one. Real Ed25519 is covered in
test_signing.py.
"""

import base64
import unittest

from certifiles.checkpoint import (
    Checkpoint,
    CheckpointError,
    Signature,
    SignedCheckpoint,
    add_signature,
    key_hash,
    meets_quorum,
    parse,
    sign,
    verified_signers,
)

ORIGIN = "certifiles.com/log/2026"
ROOT = bytes(range(32))


def checkpoint(**overrides) -> Checkpoint:
    fields = {"origin": ORIGIN, "size": 812, "root_hash": ROOT}
    fields.update(overrides)
    return Checkpoint(**fields)


class StubVerifier:
    """Accepts a signature when it equals the body reversed under that key."""

    def __init__(self, accept: bool = True) -> None:
        self.accept = accept

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return self.accept and signature == _fake_signature(public_key, message)


class StubSigner:
    def __init__(self, key_name: str, public_key: bytes) -> None:
        self.key_name = key_name
        self.public_key = public_key

    def sign(self, message: bytes) -> bytes:
        return _fake_signature(self.public_key, message)


def _fake_signature(public_key: bytes, message: bytes) -> bytes:
    import hashlib

    return hashlib.sha512(public_key + message).digest()


class TestBody(unittest.TestCase):
    def test_body_bytes_are_pinned(self):
        # These are the bytes a witness signs. A change here invalidates every
        # signature ever produced, so it is a format version change rather
        # than a test update.
        self.assertEqual(
            checkpoint().body(),
            (ORIGIN + "\n812\n" + base64.b64encode(ROOT).decode() + "\n").encode(),
        )

    def test_extensions_appear_after_the_root_hash(self):
        body = checkpoint(extensions=("witness v1", "note")).body()
        self.assertTrue(body.endswith(b"\nwitness v1\nnote\n"))

    def test_body_ends_with_newline(self):
        self.assertTrue(checkpoint().body().endswith(b"\n"))

    def test_size_zero_is_representable(self):
        self.assertIn(b"\n0\n", checkpoint(size=0).body())

    def test_invalid_checkpoints_are_rejected(self):
        for name, kwargs in {
            "empty origin": {"origin": ""},
            "origin with space first": {"origin": " leading"},
            "negative size": {"size": -1},
            "short root": {"root_hash": b"\x00" * 31},
            "long root": {"root_hash": b"\x00" * 33},
            "multiline extension": {"extensions": ("a\nb",)},
            "empty extension": {"extensions": ("",)},
        }.items():
            with self.subTest(case=name):
                with self.assertRaises(CheckpointError):
                    checkpoint(**kwargs)


class TestKeyHash(unittest.TestCase):
    def test_name_is_bound_into_the_hash(self):
        # Otherwise a signature could be reattributed to a different witness.
        key = b"\x11" * 32
        self.assertNotEqual(key_hash("witness-a", key), key_hash("witness-b", key))

    def test_key_is_bound_into_the_hash(self):
        self.assertNotEqual(
            key_hash("witness-a", b"\x11" * 32), key_hash("witness-a", b"\x22" * 32)
        )

    def test_hash_is_four_bytes(self):
        self.assertEqual(len(key_hash("witness-a", b"\x11" * 32)), 4)

    def test_key_name_with_space_is_rejected(self):
        with self.assertRaises(CheckpointError):
            key_hash("witness a", b"\x11" * 32)


class TestSignatureValidation(unittest.TestCase):
    """Found by adversarial review: a producer must not emit what its own
    parser rejects, and a verifier must not raise on anything it is handed."""

    def valid_parts(self):
        return "witness-a", b"\x00" * 4, b"\x00" * 64

    def test_valid_signature_constructs(self):
        Signature(*self.valid_parts())

    def test_malformed_signature_cannot_be_constructed(self):
        name, kh, sig = self.valid_parts()
        for case, args in {
            "key name with space": ("has space", kh, sig),
            "empty key name": ("", kh, sig),
            "short key hash": (name, b"\x00" * 3, sig),
            "long key hash": (name, b"\x00" * 5, sig),
            "empty key hash": (name, b"", sig),
            "short signature": (name, kh, b"\x00" * 63),
            "long signature": (name, kh, b"\x00" * 65),
            "empty signature": (name, kh, b""),
        }.items():
            with self.subTest(case=case):
                with self.assertRaises(CheckpointError):
                    Signature(*args)

    def test_everything_serializable_is_parseable(self):
        signer = StubSigner("witness-a", b"\x11" * 32)
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), signer))
        parse(signed.serialize())

    def test_verifier_does_not_raise_on_hostile_input(self):
        # The dataclass now blocks the original path to this, so the check is
        # that a key name which cannot be hashed is treated as unverified
        # rather than propagating an exception to the quorum decision.
        signer = StubSigner("witness-a", b"\x11" * 32)
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), signer))
        result = verified_signers(signed, {"witness a": b"\x11" * 32}, StubVerifier())
        self.assertEqual(result, frozenset())


class TestRoundTrip(unittest.TestCase):
    def test_unsigned_checkpoint_round_trips(self):
        original = SignedCheckpoint(checkpoint())
        self.assertEqual(parse(original.serialize()), original)

    def test_signed_checkpoint_round_trips(self):
        signer = StubSigner("witness-a", b"\x11" * 32)
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), signer))
        self.assertEqual(parse(signed.serialize()), signed)

    def test_extensions_round_trip(self):
        original = SignedCheckpoint(checkpoint(extensions=("ext one", "ext two")))
        self.assertEqual(parse(original.serialize()).checkpoint.extensions,
                         ("ext one", "ext two"))

    def test_multiple_signatures_round_trip(self):
        signed = SignedCheckpoint(checkpoint())
        for name in ("witness-a", "witness-b", "witness-c"):
            signed = add_signature(
                signed, sign(checkpoint(), StubSigner(name, name.encode().ljust(32)))
            )
        self.assertEqual(len(parse(signed.serialize()).signatures), 3)


class TestStrictParsing(unittest.TestCase):
    def valid_bytes(self) -> bytes:
        signer = StubSigner("witness-a", b"\x11" * 32)
        signed = add_signature(SignedCheckpoint(checkpoint()), sign(checkpoint(), signer))
        return signed.serialize()

    def test_valid_input_parses(self):
        parse(self.valid_bytes())

    def test_missing_trailing_newline_is_rejected(self):
        with self.assertRaises(CheckpointError):
            parse(self.valid_bytes().rstrip(b"\n"))

    def test_missing_blank_line_is_rejected(self):
        with self.assertRaises(CheckpointError):
            parse(checkpoint().body())

    def test_non_canonical_size_is_rejected(self):
        for bad in (b"0812", b"+812", b" 812", b"812 ", b"8_12", b"-1", b""):
            data = self.valid_bytes().replace(b"\n812\n", b"\n" + bad + b"\n", 1)
            with self.subTest(size=bad):
                with self.assertRaises(CheckpointError):
                    parse(data)

    def test_bad_root_hash_is_rejected(self):
        good = base64.b64encode(ROOT)
        for bad in (base64.b64encode(b"\x00" * 31), b"not base64!!", b""):
            data = self.valid_bytes().replace(good, bad, 1)
            with self.subTest(root=bad[:12]):
                with self.assertRaises(CheckpointError):
                    parse(data)

    def test_signature_line_without_em_dash_is_rejected(self):
        data = self.valid_bytes().replace("— ".encode(), b"- ", 1)
        with self.assertRaises(CheckpointError):
            parse(data)

    def test_signature_line_without_blob_is_rejected(self):
        body = checkpoint().body()
        with self.assertRaises(CheckpointError):
            parse(body + "\n— witness-a\n".encode())

    def test_signature_blob_of_wrong_length_is_rejected(self):
        body = checkpoint().body()
        for raw in (b"\x00" * 67, b"\x00" * 69, b""):
            blob = base64.b64encode(raw).decode()
            with self.subTest(length=len(raw)):
                with self.assertRaises(CheckpointError):
                    parse(body + f"\n— witness-a {blob}\n".encode())

    def test_base64_is_strict_against_malleability(self):
        # Lenient base64 discards characters outside the alphabet, so a space
        # inserted into the root hash decodes to the *same* 32 bytes. Two
        # different byte sequences would then parse to one checkpoint, and
        # disagreement about the signed bytes is indistinguishable from a
        # forgery. Mutation testing found this: the earlier bad-base64 case
        # was caught by the length check, never by strictness.
        good = base64.b64encode(ROOT).decode()
        for mangled in (good[:10] + " " + good[10:], good[:10] + "\t" + good[10:]):
            data = self.valid_bytes().replace(good.encode(), mangled.encode(), 1)
            with self.subTest(mangled=repr(mangled[:16])):
                self.assertEqual(base64.b64decode(mangled), ROOT, "premise: same bytes")
                with self.assertRaises(CheckpointError):
                    parse(data)

    def test_signature_blob_base64_is_strict(self):
        signer = StubSigner("witness-a", b"\x11" * 32)
        signature = sign(checkpoint(), signer)
        blob = base64.b64encode(signature.key_hash + signature.signature).decode()
        mangled = blob[:20] + " " + blob[20:]
        body = checkpoint().body()
        with self.assertRaises(CheckpointError):
            parse(body + f"\n— witness-a {mangled}\n".encode())

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(CheckpointError):
            parse(b"\xff\xfe\n0\n" + base64.b64encode(ROOT) + b"\n\n")

    def test_truncated_body_is_rejected(self):
        with self.assertRaises(CheckpointError):
            parse(b"origin\n12\n\n")


class TestQuorum(unittest.TestCase):
    def setUp(self):
        self.keys = {
            "witness-a": b"\x11" * 32,
            "witness-b": b"\x22" * 32,
        }
        self.verifier = StubVerifier()
        self.signed = SignedCheckpoint(checkpoint())

    def sign_with(self, name: str) -> None:
        signer = StubSigner(name, self.keys[name])
        self.signed = add_signature(self.signed, sign(checkpoint(), signer))

    def test_valid_signature_counts(self):
        self.sign_with("witness-a")
        self.assertEqual(
            verified_signers(self.signed, self.keys, self.verifier), {"witness-a"}
        )

    def test_replayed_signature_counts_once(self):
        # The attack this guards: duplicating one witness's line until the
        # count reaches K. Quorum is distinct witnesses, not signature lines.
        self.sign_with("witness-a")
        duplicate = self.signed.signatures[0]
        for _ in range(5):
            self.signed = add_signature(self.signed, duplicate)
        self.assertEqual(len(self.signed.signatures), 6)
        self.assertEqual(
            verified_signers(self.signed, self.keys, self.verifier), {"witness-a"}
        )
        self.assertFalse(meets_quorum(self.signed, self.keys, self.verifier, 2))

    def test_two_distinct_witnesses_meet_quorum_of_two(self):
        self.sign_with("witness-a")
        self.sign_with("witness-b")
        self.assertTrue(meets_quorum(self.signed, self.keys, self.verifier, 2))

    def test_unknown_key_is_ignored_not_counted(self):
        stranger = StubSigner("witness-z", b"\x33" * 32)
        self.signed = add_signature(self.signed, sign(checkpoint(), stranger))
        self.assertEqual(verified_signers(self.signed, self.keys, self.verifier), set())

    def test_key_hash_mismatch_is_ignored(self):
        # A signature claiming a known name but carrying another key's hash.
        self.sign_with("witness-a")
        tampered = Signature(
            key_name="witness-a",
            key_hash=key_hash("witness-b", self.keys["witness-b"]),
            signature=self.signed.signatures[0].signature,
        )
        self.signed = SignedCheckpoint(checkpoint(), (tampered,))
        self.assertEqual(verified_signers(self.signed, self.keys, self.verifier), set())

    def test_invalid_signature_does_not_count(self):
        self.sign_with("witness-a")
        self.assertEqual(
            verified_signers(self.signed, self.keys, StubVerifier(accept=False)), set()
        )

    def test_signature_over_a_different_checkpoint_does_not_count(self):
        signer = StubSigner("witness-a", self.keys["witness-a"])
        other = sign(checkpoint(size=999), signer)
        self.signed = SignedCheckpoint(checkpoint(), (other,))
        self.assertEqual(verified_signers(self.signed, self.keys, self.verifier), set())

    def test_quorum_of_zero_is_met_by_nothing(self):
        self.assertTrue(meets_quorum(self.signed, self.keys, self.verifier, 0))

    def test_negative_quorum_is_rejected(self):
        with self.assertRaises(CheckpointError):
            meets_quorum(self.signed, self.keys, self.verifier, -1)


if __name__ == "__main__":
    unittest.main()
