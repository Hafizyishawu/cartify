"""The record entered into the transparency log.

Shape is fixed here rather than later because of the retrofit problem in the
threat model: assurance cannot be upgraded after the fact, so a record written
without issuer, key and policy fields is permanently second-class. The fields
exist from the first version even while the values are weak.

Two constraints from the threat model are enforced structurally rather than by
convention:

- No personal data. Identity appears only as an opaque identifier, because an
  append-only log cannot honour an erasure request (T8).
- No self-asserted registration time. A record may *declare* when its author
  says the work was made, but the only time that carries weight is the log
  position and the witnessed tree head above it (T2). Nothing here is evidence
  of when the record was registered.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import StrEnum

SCHEMA_VERSION = 1

SHA256_PATTERN = re.compile(r"\A[0-9a-f]{64}\Z")
OPAQUE_ID_PATTERN = re.compile(r"\A[A-Za-z0-9_-]{16,128}\Z")


class ClaimType(StrEnum):
    """What the issuer asserts about how the content came to exist.

    Certifiles records the claim; it does not adjudicate it. SYNTHETIC exists so
    that honest declaration of generated content is possible, which is the only
    thing this system can offer on the AI question.
    """

    CAPTURED = "captured"
    CREATED = "created"
    DERIVED = "derived"
    SYNTHETIC = "synthetic"


class AssuranceLevel(StrEnum):
    """How strongly the issuer's identity was established at issue time.

    Stored per record and never recomputed against a later policy, so a record
    reports the assurance it actually had.
    """

    UNVERIFIED = "unverified"
    EMAIL = "email"
    DOMAIN = "domain"
    CAPTURE_ATTESTED = "capture_attested"


@dataclass(frozen=True, slots=True)
class Content:
    sha256: str
    media_type: str
    size_bytes: int
    perceptual_hash: str | None = None


@dataclass(frozen=True, slots=True)
class Issuer:
    identity_id: str
    assurance_level: AssuranceLevel
    key_id: str


@dataclass(frozen=True, slots=True)
class Record:
    content: Content
    issuer: Issuer
    claim_type: ClaimType
    policy_version: int
    declared_created_at: str | None = None
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict:
        content = {
            "media_type": self.content.media_type,
            "sha256": self.content.sha256,
            "size_bytes": self.content.size_bytes,
        }
        if self.content.perceptual_hash is not None:
            content["perceptual_hash"] = self.content.perceptual_hash

        record = {
            "claim_type": str(self.claim_type),
            "content": content,
            "issuer": {
                "assurance_level": str(self.issuer.assurance_level),
                "identity_id": self.issuer.identity_id,
                "key_id": self.issuer.key_id,
            },
            "policy_version": self.policy_version,
            "schema_version": self.schema_version,
        }
        if self.declared_created_at is not None:
            record["declared_created_at"] = self.declared_created_at
        return record

    def leaf_data(self) -> bytes:
        """Canonical bytes to be hashed into the log.

        Validates first. validate() being a separate function nothing called on
        this path meant an invalid record could be canonicalised straight into
        leaf bytes, which is the one place bad input must not reach.
        """
        validate(self)
        return canonicalize(self.to_dict())


class RecordError(ValueError):
    """Rejected before it can reach the log."""


def _require_text(value: object, field: str) -> str:
    """A string that is genuinely a string and genuinely encodable.

    A lone surrogate passes every pattern check and then raises
    UnicodeEncodeError from canonicalize, which is an unhandled non-RecordError
    on the write path. A non-string passes straight through json.dumps into the
    log. Both are refused here instead.
    """
    if not isinstance(value, str):
        raise RecordError(f"{field} must be a string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise RecordError(f"{field} is not encodable as UTF-8") from exc
    return value


def validate(record: Record) -> None:
    """Reject anything that would make a record unverifiable or unerasable.

    Raises rather than returning a flag: this runs on the write path, where the
    only safe outcome for bad input is refusal.
    """
    if record.schema_version != SCHEMA_VERSION:
        raise RecordError(f"unsupported schema_version {record.schema_version}")
    for field_name, value in (
        ("content.sha256", record.content.sha256),
        ("content.media_type", record.content.media_type),
        ("issuer.identity_id", record.issuer.identity_id),
        ("issuer.key_id", record.issuer.key_id),
    ):
        _require_text(value, field_name)
    if record.content.perceptual_hash is not None:
        _require_text(record.content.perceptual_hash, "content.perceptual_hash")
    if record.declared_created_at is not None:
        _require_text(record.declared_created_at, "declared_created_at")
    if not isinstance(record.content.size_bytes, int) or isinstance(
        record.content.size_bytes, bool
    ):
        raise RecordError("content.size_bytes must be an integer")
    if not isinstance(record.policy_version, int) or isinstance(
        record.policy_version, bool
    ):
        raise RecordError("policy_version must be an integer")
    if not SHA256_PATTERN.match(record.content.sha256):
        raise RecordError("content.sha256 must be 64 lowercase hex characters")
    if record.content.size_bytes < 0:
        raise RecordError("content.size_bytes must not be negative")
    if not record.content.media_type:
        raise RecordError("content.media_type is required")
    if record.policy_version < 1:
        raise RecordError("policy_version must be 1 or greater")

    # An identifier that looks like contact details puts erasable data into an
    # unerasable structure, so the shape is constrained rather than trusted.
    if not OPAQUE_ID_PATTERN.match(record.issuer.identity_id):
        raise RecordError(
            "issuer.identity_id must be an opaque 16-128 char token, not personal data"
        )
    # Redundant with the pattern above while that pattern stays strict, and
    # deliberately kept: mutation testing showed each check catches an email
    # on its own, so loosening the character class later cannot silently let
    # contact details into a structure that can never be erased.
    if "@" in record.issuer.identity_id:
        raise RecordError("issuer.identity_id must not contain an email address")
    if not record.issuer.key_id:
        raise RecordError("issuer.key_id is required")


def canonicalize(value: dict) -> bytes:
    """Deterministic JSON bytes: sorted keys, no insignificant whitespace, UTF-8.

    Floats are rejected rather than formatted. Cross-language agreement on
    float rendering is the hardest part of any canonicalization scheme, and no
    field in this record needs one, so the ambiguity is removed instead of
    solved. A verifier in another language must reproduce these bytes exactly
    or every proof over them fails.
    """
    _reject_floats(value)
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _reject_floats(value, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise RecordError(f"{path}: object keys must be strings")
            _reject_floats(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _reject_floats(item, f"{path}[{index}]")
    elif isinstance(value, float):
        raise RecordError(f"{path}: floats are not representable canonically")
    elif not isinstance(value, (str, int, bool, type(None))):
        raise RecordError(f"{path}: unsupported type {type(value).__name__}")
