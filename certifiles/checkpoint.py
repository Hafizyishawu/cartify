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
from typing import Protocol, Sequence

ED25519_ALGORITHM = 0x01

SIGNATURE_PREFIX = "— "
KEY_HASH_SIZE = 4
ED25519_SIGNATURE_SIZE = 64
ROOT_HASH_SIZE = 32

ORIGIN_PATTERN = re.compile(r"\A[\x21-\x7e][\x20-\x7e]*\Z")
KEY_NAME_PATTERN = re.compile(r"\A[\x21-\x7e]+\Z")
SIZE_PATTERN = re.compile(r"\A(0|[1-9][0-9]*)\Z")


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
            if not line or "\n" in line:
                raise CheckpointError("extension lines must be non-empty and single-line")

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
    if not SIZE_PATTERN.match(size_line):
        raise CheckpointError("size must be a canonical decimal integer")
    root_hash = _decode_base64(root_line, ROOT_HASH_SIZE, "root hash")

    checkpoint = Checkpoint(
        origin=origin,
        size=int(size_line),
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
    return raw


def verified_signers(
    signed: SignedCheckpoint,
    known_keys: dict[str, bytes],
    verifier: SignatureVerifier,
) -> frozenset[str]:
    """Names of known keys whose signature over this checkpoint is valid.

    Returns a set, so a replayed signature line cannot be counted twice. That
    matters directly: quorum in ADR 0001 is a count of *distinct* witnesses,
    and a duplicate-tolerant count would let one cosignature satisfy K on its
    own.

    A signature from an unknown key, or one whose key hash does not match the
    name it claims, is treated as absent rather than as an error — the policy
    question is whether K distinct known witnesses signed, not whether a
    stranger also did.
    """
    body = signed.checkpoint.body()
    verified: set[str] = set()
    for signature in signed.signatures:
        public_key = known_keys.get(signature.key_name)
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
            verified.add(signature.key_name)
    return frozenset(verified)


def meets_quorum(
    signed: SignedCheckpoint,
    known_keys: dict[str, bytes],
    verifier: SignatureVerifier,
    required: int,
) -> bool:
    """Whether at least `required` distinct known witnesses signed."""
    if required < 0:
        raise CheckpointError("required quorum must not be negative")
    return len(verified_signers(signed, known_keys, verifier)) >= required


def known_key_names(signed: SignedCheckpoint) -> Sequence[str]:
    return tuple(s.key_name for s in signed.signatures)
