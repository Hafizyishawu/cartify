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
    policy_in_force,
    CheckpointError,
    Signature,
    SignedCheckpoint,
    WitnessPolicy,
    add_signature,
    key_hash,
    meets_quorum,
    parse,
    sign,
    verified_witnesses,
    verify_log_signature,
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
        pol = WitnessPolicy(
            version=1,
            effective_from_size=0,
            log_key_name="certifiles.example/log",
            log_public_key=b"\x99" * 32,
            witnesses={"witness-b": b"\x22" * 32},
            required=1,
        )
        self.assertEqual(verified_witnesses(signed, pol, StubVerifier()), frozenset())


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

    def test_non_canonical_base64_is_rejected(self):
        # validate=True only rejects out-of-alphabet characters; it still
        # accepts a padded group whose ignored trailing bits are non-zero, so
        # one checkpoint had four wire forms per base64 field. Same quorum,
        # different digest, which defeats byte-comparison split-view detection.
        alphabet = ("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz0123456789+/")
        good = base64.b64encode(ROOT).decode()
        tried = 0
        for char in alphabet:
            variant = good[:-2] + char + "="
            if variant == good:
                continue
            try:
                if base64.b64decode(variant, validate=True) != ROOT:
                    continue
            except Exception:
                continue
            tried += 1
            data = self.valid_bytes().replace(good.encode(), variant.encode(), 1)
            with self.subTest(variant=variant[-4:]):
                self.assertNotEqual(data, self.valid_bytes())
                with self.assertRaises(CheckpointError):
                    parse(data)
        self.assertGreater(tried, 0, "premise: alternative encodings exist")

    def test_parse_then_serialize_is_byte_identical(self):
        original = self.valid_bytes()
        self.assertEqual(parse(original).serialize(), original)

    def test_implausibly_long_size_raises_checkpoint_error(self):
        # int() on a long digit string raises CPython's 4300-digit ValueError,
        # so an endpoint mapping CheckpointError to 400 returned 500 instead.
        for digits in (21, 5000, 100_000):
            data = (b"log\n" + b"9" * digits + b"\n"
                    + base64.b64encode(ROOT) + b"\n\n")
            with self.subTest(digits=digits):
                with self.assertRaises(CheckpointError):
                    parse(data)

    def test_extension_line_terminators_are_rejected(self):
        # CR, VT, FF, NEL, LS, PS and FS end a line for str.splitlines() but not
        # for a "\n" split, so an unconstrained extension lets two readers
        # disagree about how many lines the signed body has.
        for name, char in {
            "CR": "\r", "VT": "\x0b", "FF": "\x0c", "NEL": "\x85",
            "LS": "\u2028", "PS": "\u2029", "FS": "\x1c",
        }.items():
            with self.subTest(char=name):
                with self.assertRaises(CheckpointError):
                    Checkpoint(ORIGIN, 5, ROOT, extensions=(f"x{char}99",))

    def test_invalid_utf8_is_rejected(self):
        with self.assertRaises(CheckpointError):
            parse(b"\xff\xfe\n0\n" + base64.b64encode(ROOT) + b"\n\n")

    def test_truncated_body_is_rejected(self):
        with self.assertRaises(CheckpointError):
            parse(b"origin\n12\n\n")


LOG_KEY = b"\x99" * 32
KEY_A = b"\x11" * 32
KEY_B = b"\x22" * 32


def policy(required: int = 1, **overrides) -> WitnessPolicy:
    fields = {
        "version": 1,
        "effective_from_size": 0,
        "log_key_name": "certifiles.example/log",
        "log_public_key": LOG_KEY,
        "witnesses": {"witness-a": KEY_A, "witness-b": KEY_B},
        "required": required,
    }
    fields.update(overrides)
    return WitnessPolicy(**fields)


def signed_by(*names_and_keys) -> SignedCheckpoint:
    result = SignedCheckpoint(checkpoint())
    for name, key in names_and_keys:
        result = add_signature(result, sign(checkpoint(), StubSigner(name, key)))
    return result


class TestWitnessPolicy(unittest.TestCase):
    """Regressions for the two quorum bypasses found by adversarial review."""

    def test_log_key_cannot_be_a_witness_key(self):
        # The operator holds the log key. Counting it toward K meant one real
        # witness satisfied the stage-2 gate that governs the paid tier.
        with self.assertRaises(CheckpointError):
            policy(witnesses={"witness-a": KEY_A, "sneaky": LOG_KEY})

    def test_log_key_name_cannot_be_a_witness_name(self):
        with self.assertRaises(CheckpointError):
            policy(witnesses={"certifiles.example/log": KEY_A})

    def test_one_key_under_two_names_is_rejected(self):
        # Name is the operator-authored side of the mapping; key is identity.
        with self.assertRaises(CheckpointError):
            policy(witnesses={"witness-a": KEY_A, "witness-a-rotated": KEY_A})

    def test_quorum_larger_than_the_witness_set_is_rejected(self):
        with self.assertRaises(CheckpointError):
            policy(required=3)

    def test_negative_quorum_is_rejected(self):
        with self.assertRaises(CheckpointError):
            policy(required=-1)

    def test_valid_policy_constructs(self):
        policy(required=2)

    def test_a_policy_must_carry_a_version_and_an_effective_size(self):
        # ADR 0001 rules 2 and 3: a policy takes effect at a tree size, and a
        # record's assurance comes from the version in force at its size. A
        # policy that could only express "now" made both unenforceable.
        for bad in ({"version": 0}, {"version": -1}, {"effective_from_size": -1}):
            with self.subTest(**bad):
                with self.assertRaises(CheckpointError):
                    policy(**bad)

    def test_the_policy_in_force_is_chosen_by_tree_size(self):
        first = policy(version=1, effective_from_size=0, required=0, witnesses={})
        second = policy(version=2, effective_from_size=4_000, required=2)
        policies = [first, second]
        self.assertEqual(policy_in_force(policies, 0).version, 1)
        self.assertEqual(policy_in_force(policies, 3_999).version, 1)
        self.assertEqual(policy_in_force(policies, 4_000).version, 2)
        self.assertEqual(policy_in_force(policies, 9_999).version, 2)

    def test_a_size_before_any_policy_is_refused_not_defaulted(self):
        # Defaulting would silently assign an assurance level to a record that
        # no policy ever covered.
        with self.assertRaises(CheckpointError):
            policy_in_force([policy(effective_from_size=100)], 50)

    def test_policy_selection_needs_a_policy(self):
        with self.assertRaises(CheckpointError):
            policy_in_force([], 0)

    def test_counting_dedupes_by_key_even_if_the_policy_is_bypassed(self):
        # verified_witnesses is documented as the second of two barriers. The
        # policy constructor is the first and blocks this state, so reaching it
        # requires forcing the field past __post_init__.
        pol = policy(required=2)
        object.__setattr__(pol, "witnesses", {"witness-a": KEY_A, "witness-a-rot": KEY_A})
        signed = signed_by(("witness-a", KEY_A), ("witness-a-rot", KEY_A))
        self.assertEqual(len(verified_witnesses(signed, pol, StubVerifier())), 1)


class TestQuorum(unittest.TestCase):
    def setUp(self):
        self.verifier = StubVerifier()

    def test_log_signature_alone_does_not_meet_quorum(self):
        # The core regression: the log signing itself is not a witness.
        signed = signed_by(("certifiles.example/log", LOG_KEY))
        self.assertTrue(verify_log_signature(signed, policy(), self.verifier))
        self.assertEqual(verified_witnesses(signed, policy(), self.verifier), frozenset())
        self.assertFalse(meets_quorum(signed, policy(required=1), self.verifier))

    def test_log_plus_one_witness_does_not_meet_k_of_two(self):
        signed = signed_by(("certifiles.example/log", LOG_KEY), ("witness-a", KEY_A))
        self.assertFalse(meets_quorum(signed, policy(required=2), self.verifier))

    def test_log_plus_two_witnesses_meets_k_of_two(self):
        signed = signed_by(
            ("certifiles.example/log", LOG_KEY),
            ("witness-a", KEY_A),
            ("witness-b", KEY_B),
        )
        self.assertTrue(meets_quorum(signed, policy(required=2), self.verifier))

    def test_witnesses_without_the_log_signature_do_not_meet_quorum(self):
        # ADR 0001 requires the log's signature *plus* K witnesses.
        signed = signed_by(("witness-a", KEY_A), ("witness-b", KEY_B))
        self.assertFalse(meets_quorum(signed, policy(required=2), self.verifier))

    def test_replayed_witness_signature_counts_once(self):
        signed = signed_by(("certifiles.example/log", LOG_KEY), ("witness-a", KEY_A))
        duplicate = signed.signatures[-1]
        for _ in range(5):
            signed = add_signature(signed, duplicate)
        self.assertEqual(
            verified_witnesses(signed, policy(), self.verifier), {"witness-a"}
        )
        self.assertFalse(meets_quorum(signed, policy(required=2), self.verifier))

    def test_unknown_key_is_ignored(self):
        signed = signed_by(
            ("certifiles.example/log", LOG_KEY), ("witness-z", b"\x33" * 32)
        )
        self.assertEqual(verified_witnesses(signed, policy(), self.verifier), frozenset())

    def test_key_hash_mismatch_is_ignored(self):
        signed = signed_by(("witness-a", KEY_A))
        tampered = Signature(
            key_name="witness-a",
            key_hash=key_hash("witness-b", KEY_B),
            signature=signed.signatures[0].signature,
        )
        self.assertEqual(
            verified_witnesses(SignedCheckpoint(checkpoint(), (tampered,)),
                               policy(), self.verifier),
            frozenset(),
        )

    def test_invalid_signature_does_not_count(self):
        signed = signed_by(("witness-a", KEY_A))
        self.assertEqual(
            verified_witnesses(signed, policy(), StubVerifier(accept=False)), frozenset()
        )

    def test_signature_over_a_different_checkpoint_does_not_count(self):
        other = sign(checkpoint(size=999), StubSigner("witness-a", KEY_A))
        signed = SignedCheckpoint(checkpoint(), (other,))
        self.assertEqual(verified_witnesses(signed, policy(), self.verifier), frozenset())

    def test_stage_zero_needs_the_log_signature_but_no_witnesses(self):
        # ADR 0001 stage 0: K=0 is legitimate, but the log must still sign.
        stage0 = policy(required=0, witnesses={})
        self.assertFalse(meets_quorum(SignedCheckpoint(checkpoint()), stage0, self.verifier))
        signed = signed_by(("certifiles.example/log", LOG_KEY))
        self.assertTrue(meets_quorum(signed, stage0, self.verifier))


if __name__ == "__main__":
    unittest.main()
