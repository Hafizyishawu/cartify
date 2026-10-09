"""Signed tree heads in the note format used by transparency logs.

A checkpoint is what a witness cosigns and what a verifier checks a record's
inclusion proof against. The wire format matters more than the implementation
language: an external witness runs its own code, so anything Certifiles emits
has to be byte-compatible with the note format the existing witness ecosystem
already speaks.

Layout, with the body ending in a newline, then a blank line, then one
signature line per signer:

    <origin>
    <size>
    <base64 root hash>
    [extension lines]

    — <key name> <base64 keyhash||signature>

This module is deliberately free of cryptography. It builds and parses the
format, computes key hashes, and defines the signing and verification
boundary; the algorithm itself lives behind that boundary so a KMS-backed
signer can replace an in-process one without touching the format. See
certifiles/signing.py.

The format here follows the note and tlog-checkpoint conventions as
understood at the time of writing. Validate against the published C2SP
specification before interoperating with a real witness — self-consistency
is not conformance.
"""

from __future__ import annotations

import base64
import hashlib
import re
from dataclasses import dataclass, field
from collections.abc import Mapping
from typing import Protocol, Sequence

ED25519_ALGORITHM = 0x01

SIGNATURE_PREFIX = "— "
KEY_HASH_SIZE = 4
ED25519_SIGNATURE_SIZE = 64
ROOT_HASH_SIZE = 32

ORIGIN_PATTERN = re.compile(r"\A[\x21-\x7e][\x20-\x7e]*\Z")
EXTENSION_PATTERN = re.compile(r"\A[\x21-\x7e][\x20-\x7e]*\Z")
KEY_NAME_PATTERN = re.compile(r"\A[\x21-\x7e]+\Z")
SIZE_PATTERN = re.compile(r"\A(0|[1-9][0-9]*)\Z")
# A tree size cannot plausibly exceed 20 digits. Without a bound, int() on a
# long digit string raises CPython's 4300-digit ValueError rather than a
# CheckpointError, so an endpoint mapping CheckpointError to 400 returns 500
# instead - the verification denial of service named in threat model T5.
MAX_SIZE_DIGITS = 20


class CheckpointError(ValueError):
    """Malformed checkpoint. Never raised at a verifier; parsing returns it."""


class Signer(Protocol):
    """Produces a signature over a checkpoint body.

    Intentionally narrow. An implementation may hold a key in memory for
    tests, or call out to a KMS that never releases key material — the format
    code cannot tell the difference, which is the point. Nothing here accepts
    or returns a private key.
    """

    @property
    def key_name(self) -> str: ...

    @property
    def public_key(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


class SignatureVerifier(Protocol):
    """Checks one signature against one public key."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool: ...


def key_hash(key_name: str, public_key: bytes) -> bytes:
    """Short identifier binding a key to its name.

    The name is bound into the hash so the same key published under a
    different name produces a different identifier, and a signature cannot be
    silently reattributed to another witness.
    """
    if not KEY_NAME_PATTERN.match(key_name):
        raise CheckpointError("key name must be printable with no spaces")
    digest = hashlib.sha256(
        key_name.encode("utf-8")
        + b"\n"
        + bytes([ED25519_ALGORITHM])
        + public_key
    ).digest()
    return digest[:KEY_HASH_SIZE]


@dataclass(frozen=True, slots=True)
class Checkpoint:
    origin: str
    size: int
    root_hash: bytes
    extensions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not ORIGIN_PATTERN.match(self.origin):
            raise CheckpointError("origin must be a non-empty printable line")
        if self.size < 0:
            raise CheckpointError("size must not be negative")
        if len(self.root_hash) != ROOT_HASH_SIZE:
            raise CheckpointError(f"root hash must be {ROOT_HASH_SIZE} bytes")
        for line in self.extensions:
            # CR, VT, FF, NEL, LS, PS and FS all terminate a line for
            # str.splitlines() but not for a "\n"-only split, so an unconstrained
            # extension lets two readers disagree about how many lines the signed
            # body has. Same character class as origin closes that.
            if not EXTENSION_PATTERN.match(line):
                raise CheckpointError(
                    "extension lines must be non-empty printable ASCII"
                )

    def body(self) -> bytes:
        """The exact bytes a signature covers."""
        lines = [
            self.origin,
            str(self.size),
            base64.b64encode(self.root_hash).decode("ascii"),
            *self.extensions,
        ]
        return ("\n".join(lines) + "\n").encode("utf-8")


@dataclass(frozen=True, slots=True)
class Signature:
    key_name: str
    key_hash: bytes
    signature: bytes

    def __post_init__(self) -> None:
        # Without this, a Signature built directly rather than through parse()
        # can hold values that serialize() will happily emit and parse() will
        # then reject — a producer writing output its own reader refuses.
        if not KEY_NAME_PATTERN.match(self.key_name):
            raise CheckpointError("key name must be printable with no spaces")
        if len(self.key_hash) != KEY_HASH_SIZE:
            raise CheckpointError(f"key hash must be {KEY_HASH_SIZE} bytes")
        if len(self.signature) != ED25519_SIGNATURE_SIZE:
            raise CheckpointError(
                f"signature must be {ED25519_SIGNATURE_SIZE} bytes"
            )

    def line(self) -> str:
        blob = base64.b64encode(self.key_hash + self.signature).decode("ascii")
        return f"{SIGNATURE_PREFIX}{self.key_name} {blob}"


@dataclass(frozen=True, slots=True)
class SignedCheckpoint:
    checkpoint: Checkpoint
    signatures: tuple[Signature, ...] = field(default=())

    def serialize(self) -> bytes:
        parts = [self.checkpoint.body(), b"\n"]
        parts.extend((s.line() + "\n").encode("utf-8") for s in self.signatures)
        return b"".join(parts)


def sign(checkpoint: Checkpoint, signer: Signer) -> Signature:
    body = checkpoint.body()
    signature = signer.sign(body)
    if len(signature) != ED25519_SIGNATURE_SIZE:
        raise CheckpointError("signer returned a signature of the wrong length")
    return Signature(
        key_name=signer.key_name,
        key_hash=key_hash(signer.key_name, signer.public_key),
        signature=signature,
    )


def add_signature(signed: SignedCheckpoint, signature: Signature) -> SignedCheckpoint:
    return SignedCheckpoint(signed.checkpoint, signed.signatures + (signature,))


def parse(data: bytes) -> SignedCheckpoint:
    """Parse untrusted checkpoint bytes.

    Strict by construction. Every tolerance here — a stray blank line, a
    lenient integer, an over-long signature blob — is a way for two
    implementations to disagree about what was signed, and disagreement about
    the signed bytes is indistinguishable from a forgery.
    """
    if not data.endswith(b"\n"):
        raise CheckpointError("checkpoint must end with a newline")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CheckpointError("checkpoint must be valid UTF-8") from exc

    try:
        body_text, signature_text = text.split("\n\n", 1)
    except ValueError as exc:
        raise CheckpointError("missing blank line between body and signatures") from exc

    body_lines = body_text.split("\n")
    if len(body_lines) < 3:
        raise CheckpointError("body must have origin, size and root hash")

    origin, size_line, root_line, *extensions = body_lines
    if len(size_line) > MAX_SIZE_DIGITS:
        raise CheckpointError("size has implausibly many digits")
    if not SIZE_PATTERN.match(size_line):
        raise CheckpointError("size must be a canonical decimal integer")
    try:
        size = int(size_line)
    except ValueError as exc:
        raise CheckpointError("size is not an integer") from exc
    root_hash = _decode_base64(root_line, ROOT_HASH_SIZE, "root hash")

    checkpoint = Checkpoint(
        origin=origin,
        size=size,
        root_hash=root_hash,
        extensions=tuple(extensions),
    )

    signature_lines = signature_text.split("\n")
    if signature_lines[-1] != "":
        raise CheckpointError("signature block must end with a newline")
    signatures = tuple(_parse_signature(line) for line in signature_lines[:-1])
    return SignedCheckpoint(checkpoint, signatures)


def _parse_signature(line: str) -> Signature:
    if not line.startswith(SIGNATURE_PREFIX):
        raise CheckpointError("signature line must start with an em dash and a space")
    remainder = line[len(SIGNATURE_PREFIX):]
    key_name, separator, blob = remainder.partition(" ")
    if not separator:
        raise CheckpointError("signature line must have a key name and a blob")
    if not KEY_NAME_PATTERN.match(key_name):
        raise CheckpointError("key name must be printable with no spaces")
    raw = _decode_base64(blob, KEY_HASH_SIZE + ED25519_SIGNATURE_SIZE, "signature")
    return Signature(
        key_name=key_name,
        key_hash=raw[:KEY_HASH_SIZE],
        signature=raw[KEY_HASH_SIZE:],
    )


def _decode_base64(value: str, expected_length: int, what: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as exc:
        raise CheckpointError(f"{what} is not valid base64") from exc
    if len(raw) != expected_length:
        raise CheckpointError(f"{what} must decode to {expected_length} bytes")
    # validate=True only rejects characters outside the alphabet. It still
    # accepts a padded group whose ignored trailing bits are non-zero, so
    # several encodings decode to identical bytes. That would give one
    # checkpoint multiple valid wire forms with the same quorum but different
    # digests, defeating any split-view detection that compares checkpoint
    # bytes. Re-encoding and comparing forces exactly one representation.
    if base64.b64encode(raw).decode("ascii") != value:
        raise CheckpointError(f"{what} is not canonically encoded")
    return raw


@dataclass(frozen=True, slots=True)
class WitnessPolicy:
    """ADR 0001's quorum rule, as a type that cannot express a bypass.

    Two mistakes are made structurally impossible here rather than left to the
    caller to avoid. Both were live defects while the witness set was a flat
    name-to-key mapping:

    - The log's own key could be counted toward K. The operator holds that key,
      and the operator is the attacker this whole design exists to constrain,
      so K=2 was satisfiable with a single real witness.
    - One key registered under two names counted as two witnesses, because the
      unit of identity was the name — the side of the mapping the operator
      authors — rather than the key.
    """

    version: int
    effective_from_size: int
    log_key_name: str
    log_public_key: bytes
    witnesses: Mapping[str, bytes]
    required: int

    def __post_init__(self) -> None:
        # ADR 0001 rule 2: a policy takes effect at a tree size, not a
        # wall-clock time, because wall-clock is operator controlled and tree
        # size is not. Rule 3: a record's assurance is derived from the version
        # in force at its size and never recomputed against the current policy.
        # A policy type that could only express "now" made both unenforceable.
        if not isinstance(self.version, int) or self.version < 1:
            raise CheckpointError("policy version must be 1 or greater")
        if not isinstance(self.effective_from_size, int) or self.effective_from_size < 0:
            raise CheckpointError("effective_from_size must not be negative")
        if self.required < 0:
            raise CheckpointError("required quorum must not be negative")
        if self.required > len(self.witnesses):
            raise CheckpointError(
                "required quorum exceeds the number of witnesses in the policy"
            )
        key_hash(self.log_key_name, self.log_public_key)
        keys = [bytes(k) for k in self.witnesses.values()]
        if len(set(keys)) != len(keys):
            raise CheckpointError(
                "witness set contains one public key under more than one name"
            )
        if bytes(self.log_public_key) in set(keys):
            raise CheckpointError("the log key must not also be a witness key")
        if self.log_key_name in self.witnesses:
            raise CheckpointError("the log key name must not also be a witness name")
        for name, key in self.witnesses.items():
            key_hash(name, key)


def _verified_pairs(
    signed: SignedCheckpoint,
    keys: Mapping[str, bytes],
    verifier: SignatureVerifier,
) -> set[tuple[str, bytes]]:
    body = signed.checkpoint.body()
    verified: set[tuple[str, bytes]] = set()
    for signature in signed.signatures:
        public_key = keys.get(signature.key_name)
        if public_key is None:
            continue
        try:
            expected = key_hash(signature.key_name, public_key)
        except CheckpointError:
            # A verifier must reach a verdict on anything it is handed. Raising
            # here would turn malformed input into an unhandled failure at the
            # point where a caller is deciding whether quorum is met.
            continue
        if signature.key_hash != expected:
            continue
        if verifier.verify(public_key, body, signature.signature):
            verified.add((signature.key_name, bytes(public_key)))
    return verified


def verify_log_signature(
    signed: SignedCheckpoint, policy: WitnessPolicy, verifier: SignatureVerifier
) -> bool:
    """Whether the log itself signed this checkpoint.

    Deliberately separate from the witness count, and its result is never a
    member of that count.
    """
    return bool(
        _verified_pairs(
            signed, {policy.log_key_name: policy.log_public_key}, verifier
        )
    )


def verified_witnesses(
    signed: SignedCheckpoint, policy: WitnessPolicy, verifier: SignatureVerifier
) -> frozenset[str]:
    """Distinct witnesses whose signature over this checkpoint is valid.

    Deduplicated by public key, not by name: quorum in ADR 0001 counts distinct
    independent entities, and one key answering to two names is one entity. The
    policy already rejects a duplicated key, so this is the second of two
    barriers rather than the only one.

    A signature from a key outside the policy, or one whose key hash does not
    match the name it claims, is treated as absent rather than as an error. The
    question is whether K known witnesses signed, not whether a stranger also
    did.
    """
    by_key: dict[bytes, str] = {}
    for name, key in _verified_pairs(signed, policy.witnesses, verifier):
        by_key.setdefault(key, name)
    return frozenset(by_key.values())


def meets_quorum(
    signed: SignedCheckpoint, policy: WitnessPolicy, verifier: SignatureVerifier
) -> bool:
    """ADR 0001: the log's own signature plus at least K distinct witnesses."""
    if not verify_log_signature(signed, policy, verifier):
        return False
    return len(verified_witnesses(signed, policy, verifier)) >= policy.required


def signature_key_names(signed: SignedCheckpoint) -> Sequence[str]:
    """Names claimed by the signature lines. Claimed, not verified."""
    return tuple(s.key_name for s in signed.signatures)


def policy_in_force(
    policies: Sequence[WitnessPolicy], tree_size: int
) -> WitnessPolicy:
    """The policy governing a checkpoint of `tree_size`.

    Selecting by size rather than by "the current policy" is what makes ADR
    0001 rule 3 true: a record keeps the assurance it actually had, and a later
    policy change cannot retroactively restate it — upward or downward.
    """
    if not policies:
        raise CheckpointError("no witness policy is defined")
    if not isinstance(tree_size, int) or tree_size < 0:
        raise CheckpointError("tree size must not be negative")
    applicable = [p for p in policies if p.effective_from_size <= tree_size]
    if not applicable:
        raise CheckpointError(
            f"no policy is in force at tree size {tree_size}; the earliest"
            f" begins at {min(p.effective_from_size for p in policies)}"
        )
    return max(applicable, key=lambda p: (p.effective_from_size, p.version))
