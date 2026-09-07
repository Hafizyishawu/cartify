#!/usr/bin/env python3
"""Generate a small published log so the verify page can be exercised for real.

Development only. The signing key is generated in process and thrown away,
which is exactly what ADR 0001 forbids in production — the point here is to
have something to verify against, not to model key custody.
"""

import argparse
import hashlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certifiles.anchoring import AnchorKind, AnchorReceipt
from certifiles.checkpoint import SignedCheckpoint, WitnessPolicy, add_signature, sign
from certifiles.fingerprint import Fingerprint, FingerprintKind
from certifiles.log import TransparencyLog
from certifiles.publication import StaticPublication
from certifiles.record import AssuranceLevel, ClaimType, Content, Issuer, Record
from certifiles.signing import InMemoryEd25519Signer

ORIGIN = "certifiles.example/log"

AMARA = "amara-okonjo-0001"
KENJI = "kenji-tanaka-0002"

# phash and dhash are given explicitly so the demo exercises the two cases the
# wireframe shows: a genuine strong candidate, and a close-but-flat image that
# the quality floor correctly downgrades. Positions 5 and 6 are registered
# after the works they resemble, which is the direction monitoring alerts on.
DETAILED = "c3a90f7e21b45d80"
FLAT = "80c0e0f0f8fcfeff"


def bits(value: str, flipped: int) -> str:
    return f"{int(value, 16) ^ ((1 << flipped) - 1):016x}"


WORKS = [
    ("Tidal Study No. 4", AMARA, AssuranceLevel.DOMAIN, "image/tiff",
     DETAILED, bits(DETAILED, 33), 88),
    ("Harbour Wall, 6am", AMARA, AssuranceLevel.DOMAIN, "image/tiff",
     bits(DETAILED, 40), bits(DETAILED, 44), 84),
    ("Field Notes (i)", AMARA, AssuranceLevel.DOMAIN, "image/png",
     FLAT, bits(FLAT, 41), 22),
    ("Salt Marsh Series, plate 2", KENJI, AssuranceLevel.EMAIL, "image/jpeg",
     bits(DETAILED, 52), bits(DETAILED, 55), 79),
    ("Winter Pilings", KENJI, AssuranceLevel.EMAIL, "image/jpeg",
     bits(DETAILED, 60), bits(DETAILED, 58), 81),
    # Close to Tidal Study on both algorithms, both images detailed: strong.
    ("Untitled (Ocean)", "unverified-8f31c2", AssuranceLevel.UNVERIFIED, "image/jpeg",
     bits(DETAILED, 2), bits(bits(DETAILED, 33), 3), 85),
    # Closer still on phash, but both images are flat: capped to weak.
    ("gradient-test-02", "unverified-2b90aa", AssuranceLevel.EMAIL, "image/png",
     bits(FLAT, 1), bits(FLAT, 60), 20),
]


def build(out: Path, witnesses: int) -> None:
    log = TransparencyLog()
    log_signer = InMemoryEd25519Signer.from_seed(ORIGIN, b"\x01" * 32)
    witness_signers = [
        InMemoryEd25519Signer.from_seed(f"witness-{n}.example.org", bytes([n + 2]) * 32)
        for n in range(witnesses)
    ]

    for index, (title, identity, assurance, media, phash, dhash, quality) in enumerate(WORKS):
        payload = f"{title}\n".encode()
        digest = hashlib.sha256(payload).hexdigest()
        log.append(
            Record(
                content=Content(
                    sha256=digest,
                    media_type=media,
                    size_bytes=len(payload),
                    fingerprints=(
                        Fingerprint(FingerprintKind.PHASH, phash),
                        Fingerprint(FingerprintKind.DHASH, dhash),
                    ),
                    quality=quality,
                ),
                issuer=Issuer(identity, assurance, "log-key-2026-09"),
                claim_type=ClaimType.CREATED,
                policy_version=1,
            )
        )
        print(f"  pos {index}  {digest[:16]}…  {title}  (q{quality})")

    checkpoint = log.checkpoint(ORIGIN)
    signed = SignedCheckpoint(checkpoint, (sign(checkpoint, log_signer),))
    for signer in witness_signers:
        signed = add_signature(signed, sign(checkpoint, signer))

    policy = WitnessPolicy(
        version=1,
        effective_from_size=0,
        log_key_name=ORIGIN,
        log_public_key=log_signer.public_key,
        witnesses={s.key_name: s.public_key for s in witness_signers},
        required=min(witnesses, 2),
    )
    anchor = AnchorReceipt(
        AnchorKind.RFC3161, log.size(), log.root(), int(time.time()),
        b"development-token", attested_at=int(time.time()),
    )

    report = StaticPublication(out).publish(
        log, signed, anchors=[anchor], policies=[policy]
    )
    print(f"\n  {report}")
    print(f"  policy: K={policy.required} of {len(policy.witnesses)} witnesses")
    log.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="web/log", type=Path)
    parser.add_argument("--witnesses", type=int, default=2)
    args = parser.parse_args()
    build(args.out, args.witnesses)
