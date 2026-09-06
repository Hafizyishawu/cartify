"""Record schema and canonicalization tests.

Canonical bytes are the contract between this implementation and any verifier
written later in another language. A change in these bytes invalidates every
proof already issued, so the tests pin the exact output rather than only
checking round-trips.
"""

import json
import unittest

from certifiles.merkle import leaf_hash
from certifiles.record import (
    AssuranceLevel,
    ClaimType,
    Content,
    Issuer,
    Record,
    RecordError,
    canonicalize,
    validate,
)

VALID_SHA = "a" * 64
VALID_ID = "op4Que-Identifier_01"


def sample(**overrides) -> Record:
    fields = {
        "content": Content(sha256=VALID_SHA, media_type="image/png", size_bytes=1024),
        "issuer": Issuer(
            identity_id=VALID_ID,
            assurance_level=AssuranceLevel.EMAIL,
            key_id="key-2026-09",
        ),
        "claim_type": ClaimType.CREATED,
        "policy_version": 1,
    }
    fields.update(overrides)
    return Record(**fields)


class TestCanonicalization(unittest.TestCase):
    def test_key_order_does_not_affect_output(self):
        a = canonicalize({"b": 1, "a": 2, "c": {"z": 1, "y": 2}})
        b = canonicalize({"c": {"y": 2, "z": 1}, "a": 2, "b": 1})
        self.assertEqual(a, b)

    def test_no_insignificant_whitespace(self):
        self.assertEqual(canonicalize({"a": 1, "b": [1, 2]}), b'{"a":1,"b":[1,2]}')

    def test_unicode_is_utf8_not_escaped(self):
        self.assertEqual(canonicalize({"k": "café"}), '{"k":"café"}'.encode("utf-8"))

    def test_floats_are_rejected(self):
        with self.assertRaises(RecordError):
            canonicalize({"size": 1.0})
        with self.assertRaises(RecordError):
            canonicalize({"nested": {"list": [1, 2.5]}})

    def test_unsupported_types_are_rejected(self):
        with self.assertRaises(RecordError):
            canonicalize({"when": object()})

    def test_output_is_valid_json_that_round_trips(self):
        record = sample()
        self.assertEqual(json.loads(record.leaf_data()), record.to_dict())

    def test_leaf_bytes_are_stable_for_equal_records(self):
        self.assertEqual(sample().leaf_data(), sample().leaf_data())

    def test_pinned_canonical_bytes(self):
        # Pinned deliberately. If this assertion needs changing, every proof
        # already issued over the old bytes is invalidated, which is a schema
        # version bump rather than a test update.
        self.assertEqual(
            sample().leaf_data(),
            (
                '{"claim_type":"created",'
                '"content":{"media_type":"image/png","sha256":"' + VALID_SHA + '",'
                '"size_bytes":1024},'
                '"issuer":{"assurance_level":"email","identity_id":"' + VALID_ID + '",'
                '"key_id":"key-2026-09"},'
                '"policy_version":1,"schema_version":1}'
            ).encode("utf-8"),
        )


class TestFieldSensitivity(unittest.TestCase):
    def test_every_field_change_changes_the_leaf_hash(self):
        base = leaf_hash(sample().leaf_data())
        variants = {
            "sha256": sample(
                content=Content(sha256="b" * 64, media_type="image/png", size_bytes=1024)
            ),
            "media_type": sample(
                content=Content(sha256=VALID_SHA, media_type="image/jpeg", size_bytes=1024)
            ),
            "size_bytes": sample(
                content=Content(sha256=VALID_SHA, media_type="image/png", size_bytes=1025)
            ),
            "perceptual_hash": sample(
                content=Content(
                    sha256=VALID_SHA,
                    media_type="image/png",
                    size_bytes=1024,
                    perceptual_hash="ff00ff00",
                )
            ),
            "assurance_level": sample(
                issuer=Issuer(VALID_ID, AssuranceLevel.DOMAIN, "key-2026-09")
            ),
            "identity_id": sample(
                issuer=Issuer("another-identity-01", AssuranceLevel.EMAIL, "key-2026-09")
            ),
            "key_id": sample(issuer=Issuer(VALID_ID, AssuranceLevel.EMAIL, "key-2026-10")),
            "claim_type": sample(claim_type=ClaimType.SYNTHETIC),
            "policy_version": sample(policy_version=2),
            "declared_created_at": sample(declared_created_at="2026-09-04T00:00:00Z"),
        }
        for name, variant in variants.items():
            with self.subTest(field=name):
                self.assertNotEqual(base, leaf_hash(variant.leaf_data()))

    def test_omitted_optional_field_differs_from_empty_string(self):
        with_none = sample().leaf_data()
        with_empty = sample(declared_created_at="").leaf_data()
        self.assertNotEqual(with_none, with_empty)


class TestValidation(unittest.TestCase):
    def test_valid_record_passes(self):
        validate(sample())

    def test_malformed_content_hash_is_rejected(self):
        for bad in ("", "xyz", "A" * 64, "a" * 63, "a" * 65):
            with self.subTest(sha=bad):
                with self.assertRaises(RecordError):
                    validate(
                        sample(
                            content=Content(
                                sha256=bad, media_type="image/png", size_bytes=1
                            )
                        )
                    )

    def test_identity_that_looks_like_personal_data_is_rejected(self):
        # T8: an append-only log cannot honour erasure, so contact details must
        # never become an identifier in the first place.
        for bad in ("hafiz@example.com", "Hafiz Yishawu", "short", "a" * 129):
            with self.subTest(identity=bad):
                with self.assertRaises(RecordError):
                    validate(
                        sample(
                            issuer=Issuer(bad, AssuranceLevel.EMAIL, "key-2026-09")
                        )
                    )

    def test_missing_key_id_is_rejected(self):
        with self.assertRaises(RecordError):
            validate(sample(issuer=Issuer(VALID_ID, AssuranceLevel.EMAIL, "")))

    def test_bad_policy_version_is_rejected(self):
        for bad in (0, -1):
            with self.subTest(version=bad):
                with self.assertRaises(RecordError):
                    validate(sample(policy_version=bad))

    def test_negative_size_is_rejected(self):
        with self.assertRaises(RecordError):
            validate(
                sample(content=Content(VALID_SHA, "image/png", -1))
            )

    def test_missing_media_type_is_rejected(self):
        with self.assertRaises(RecordError):
            validate(sample(content=Content(VALID_SHA, "", 10)))

    def test_unsupported_schema_version_is_rejected(self):
        with self.assertRaises(RecordError):
            validate(sample(schema_version=99))

    def test_record_carries_no_registration_timestamp(self):
        # Time comes from the log position and the witnessed tree head, never
        # from a field the issuer controls.
        keys = set(sample().to_dict())
        self.assertNotIn("registered_at", keys)
        self.assertNotIn("timestamp", keys)


class TestAdversarialFindings(unittest.TestCase):
    """Regressions for defects found by adversarial review."""

    def test_leaf_data_validates(self):
        # validate() was a separate function nothing on the write path called,
        # so an invalid record canonicalised straight into leaf bytes.
        invalid = sample(content=Content(sha256="NOT A HASH", media_type="", size_bytes=-5))
        with self.assertRaises(RecordError):
            invalid.leaf_data()

    def test_unpaired_surrogate_is_refused_not_crashed(self):
        # Passed every pattern check, then raised UnicodeEncodeError from
        # canonicalize — an unhandled non-RecordError on the write path.
        bad = sample(content=Content(VALID_SHA, "image/\ud800", 10))
        with self.assertRaises(RecordError):
            validate(bad)
        with self.assertRaises(RecordError):
            bad.leaf_data()

    def test_non_string_fields_are_rejected(self):
        for case, record in {
            "int media_type": sample(content=Content(VALID_SHA, 7, 10)),
            "int sha256": sample(content=Content(7, "image/png", 10)),
            "int key_id": sample(issuer=Issuer(VALID_ID, AssuranceLevel.EMAIL, 7)),
            "int identity_id": sample(issuer=Issuer(7, AssuranceLevel.EMAIL, "k")),
        }.items():
            with self.subTest(case=case):
                with self.assertRaises(RecordError):
                    validate(record)

    def test_bool_is_not_an_integer_size(self):
        with self.assertRaises(RecordError):
            validate(sample(content=Content(VALID_SHA, "image/png", True)))


if __name__ == "__main__":
    unittest.main()
