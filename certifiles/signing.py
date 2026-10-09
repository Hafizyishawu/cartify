"""Ed25519 signing and verification behind the checkpoint signer boundary.

Isolated from certifiles/checkpoint.py so the format has no cryptography
dependency and so the production signer — which must call a KMS that never
releases key material, per ADR 0001 — can replace the in-process one without
the format code changing.

Requires the `cryptography` package. It is imported lazily so that installing
it is only necessary to sign or verify, not to parse or build checkpoints.
"""

from __future__ import annotations

from certifiles.checkpoint import ED25519_SIGNATURE_SIZE, CheckpointError


def _ed25519():
    try:
        from cryptography.hazmat.primitives.asymmetric import ed25519
    except ImportError as exc:  # pragma: no cover - environment dependent
        raise CheckpointError(
            "Ed25519 signing requires the 'cryptography' package"
        ) from exc
    return ed25519


class Ed25519Verifier:
    """Verifies checkpoint signatures. Handles only public data."""

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        ed25519 = _ed25519()
        if len(signature) != ED25519_SIGNATURE_SIZE:
            return False
        try:
            loaded = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
            loaded.verify(signature, message)
        except Exception:
            # Any failure is an invalid signature. Distinguishing malformed
            # keys from bad signatures would leak detail to a caller who is,
            # by construction, untrusted.
            return False
        return True


class InMemoryEd25519Signer:
    """Development and test signer holding a private key in process memory.

    Not for production. ADR 0001 requires the log signing key to be
    non-exportable and reachable only through a service with no standing human
    access; a key in a Python process satisfies neither. This exists so the
    checkpoint format can be exercised end to end and demonstrated to a
    prospective witness before any key custody work is done.

    There is deliberately no method to load a key from a file. A convenience
    like that is how a development key ends up signing production records.
    """

    def __init__(self, key_name: str, private_key) -> None:
        self._key_name = key_name
        self._private_key = private_key

    @classmethod
    def generate(cls, key_name: str) -> "InMemoryEd25519Signer":
        ed25519 = _ed25519()
        return cls(key_name, ed25519.Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, key_name: str, seed: bytes) -> "InMemoryEd25519Signer":
        """Deterministic signer for tests. Never use a fixed seed elsewhere."""
        ed25519 = _ed25519()
        if len(seed) != 32:
            raise CheckpointError("Ed25519 seed must be 32 bytes")
        return cls(key_name, ed25519.Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def key_name(self) -> str:
        return self._key_name

    @property
    def public_key(self) -> bytes:
        from cryptography.hazmat.primitives import serialization

        return self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def sign(self, message: bytes) -> bytes:
        return self._private_key.sign(message)
