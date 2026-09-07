"""Perceptual fingerprints and the distance between them.

Computing a fingerprint from pixels belongs to the client — Cartify already
does it, and a browser can. This module holds only the values and the
arithmetic, so the log, the record and the index share one definition and none
of them needs an imaging library.

Several fingerprints are kept per work rather than one. The file is not stored,
so a fingerprint can never be recomputed later: whatever is captured at
registration is all there will ever be, and a better algorithm in two years
cannot be applied retroactively. Three cheap hashes now beat one good hash that
can never be upgraded, and an evader has to defeat all of them at once.

None of this is evidence. Perceptual hashing is adversarially malleable — an
image can be perturbed until it falls outside any radius while looking
identical — so a distance is a search hint that surfaces candidates for a human
to look at, and never a finding.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

HEX_PATTERN = re.compile(r"\A[0-9a-f]+\Z")


class FingerprintError(ValueError):
    """A fingerprint that cannot be compared with anything."""


class FingerprintKind(StrEnum):
    """The algorithms captured at registration.

    Adding a kind later is safe for new records and useless for old ones, which
    is the whole reason for capturing more than one now.
    """

    PHASH = "phash"
    DHASH = "dhash"
    PDQ = "pdq"


BIT_LENGTHS = {
    FingerprintKind.PHASH: 64,
    FingerprintKind.DHASH: 64,
    FingerprintKind.PDQ: 256,
}

# Visual detail, 0-100, computed by the client at registration. An integer
# because record canonicalization refuses floats, and because a spurious two
# decimal places would imply a precision this measure does not have.
MIN_QUALITY = 0
MAX_QUALITY = 100

# Below this, an image has too little detail for a distance to mean much: flat
# colour, line art, mostly-white graphics. Such images collide by coincidence
# far more often than photographs, so a single global threshold would flood an
# illustrator with false alerts while working acceptably for a photographer.
LOW_QUALITY_CEILING = 35


@dataclass(frozen=True, slots=True)
class Fingerprint:
    kind: FingerprintKind
    value: str

    def __post_init__(self) -> None:
        if not isinstance(self.value, str) or not HEX_PATTERN.match(self.value):
            raise FingerprintError(f"{self.kind} value must be lowercase hex")
        expected = BIT_LENGTHS[self.kind] // 4
        if len(self.value) != expected:
            raise FingerprintError(
                f"{self.kind} must be {expected} hex characters, got {len(self.value)}"
            )

    @property
    def bit_length(self) -> int:
        return BIT_LENGTHS[self.kind]

    def distance_to(self, other: "Fingerprint") -> int:
        if self.kind != other.kind:
            raise FingerprintError(
                f"cannot compare {self.kind} with {other.kind}: different algorithms"
            )
        return (int(self.value, 16) ^ int(other.value, 16)).bit_count()


def normalised_distance(distance: int, bit_length: int) -> float:
    """Distance as a fraction of the hash width, so kinds are comparable."""
    if bit_length <= 0:
        raise FingerprintError("bit length must be positive")
    return distance / bit_length


def validate_quality(quality: int) -> int:
    if not isinstance(quality, int) or isinstance(quality, bool):
        raise FingerprintError("quality must be an integer")
    if not MIN_QUALITY <= quality <= MAX_QUALITY:
        raise FingerprintError(f"quality must be {MIN_QUALITY}-{MAX_QUALITY}")
    return quality
