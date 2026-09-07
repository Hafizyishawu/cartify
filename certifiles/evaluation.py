"""Measuring near-match accuracy.

The near-match thresholds are guesses until something measures them, and the
interface shows artists a confidence band, which is an accuracy claim. This is
the instrument that turns the guess into a number.

**Building this closes nothing. Running it on real data does.** A harness that
has only ever seen modelled fingerprints proves the harness works, which is not
the same as proving the thresholds are right — so a dataset carries its
provenance, and a report refuses to recommend an operating point from anything
but measured data.

What it measures, and why these and not accuracy:

- **Precision** is the number that governs. A false positive is an accusation
  handed to an artist about someone who did nothing, and that is not symmetric
  with a missed match, which they can search for again.
- **Recall per transform**, because "we hold up under recompression and lose
  most 20% crops" is actionable and a single recall figure is not.
- **Precision and false-positive rate per quality stratum**, because the central
  design claim is that low-detail images behave differently. A harness that does
  not stratify by quality cannot validate the decision the whole banding rests
  on.

Fingerprinting images is the client's job and needs an imaging library, so this
module works on fingerprints that have already been computed. Producing a
measured dataset is a separate pipeline; the format it must emit is here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Iterable, Mapping, Sequence

from certifiles.fingerprint import (
    LOW_QUALITY_CEILING,
    Fingerprint,
    FingerprintKind,
)
from certifiles.nearmatch import LOOSE, TIGHT, Band, classify

BAND_ORDER = {Band.STRONG_CANDIDATE: 0, Band.POSSIBLE: 1, Band.WEAK: 2}


class EvaluationError(RuntimeError):
    """The harness refused to produce or interpret a result."""


class Provenance(StrEnum):
    """Where a dataset's fingerprints came from.

    MEASURED means real images went through a real fingerprinter. MODELLED
    means the distances were constructed to exercise this code. Only the first
    can support a claim about accuracy, and the distinction is carried through
    to the report rather than living in someone's memory.
    """

    MEASURED = "measured"
    MODELLED = "modelled"


@dataclass(frozen=True, slots=True)
class Sample:
    work_id: str
    fingerprints: tuple[Fingerprint, ...]
    quality: int


@dataclass(frozen=True, slots=True)
class Pair:
    left: Sample
    right: Sample
    same_work: bool
    transform: str

    def distances(self) -> dict[FingerprintKind, int]:
        left = {f.kind: f for f in self.left.fingerprints}
        right = {f.kind: f for f in self.right.fingerprints}
        shared = set(left) & set(right)
        if not shared:
            raise EvaluationError(
                f"pair {self.left.work_id}/{self.right.work_id} shares no algorithm"
            )
        return {kind: left[kind].distance_to(right[kind]) for kind in shared}

    def quality(self) -> int:
        return min(self.left.quality, self.right.quality)


@dataclass
class Dataset:
    pairs: list[Pair]
    provenance: Provenance
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.pairs:
            raise EvaluationError("a dataset needs at least one pair")

    @property
    def transforms(self) -> list[str]:
        return sorted({p.transform for p in self.pairs if p.same_work})

    def to_json(self) -> str:
        return json.dumps(
            {
                "provenance": str(self.provenance),
                "notes": self.notes,
                "pairs": [
                    {
                        "same_work": p.same_work,
                        "transform": p.transform,
                        "left": _sample_json(p.left),
                        "right": _sample_json(p.right),
                    }
                    for p in self.pairs
                ],
            },
            indent=2,
            sort_keys=True,
        )

    @classmethod
    def from_json(cls, text: str) -> "Dataset":
        payload = json.loads(text)
        return cls(
            pairs=[
                Pair(
                    left=_sample_from_json(row["left"]),
                    right=_sample_from_json(row["right"]),
                    same_work=row["same_work"],
                    transform=row["transform"],
                )
                for row in payload["pairs"]
            ],
            provenance=Provenance(payload["provenance"]),
            notes=payload.get("notes", ""),
        )


def _sample_json(sample: Sample) -> dict:
    return {
        "work_id": sample.work_id,
        "quality": sample.quality,
        "fingerprints": {str(f.kind): f.value for f in sample.fingerprints},
    }


def _sample_from_json(payload: dict) -> Sample:
    return Sample(
        work_id=payload["work_id"],
        quality=payload["quality"],
        fingerprints=tuple(
            Fingerprint(FingerprintKind(kind), value)
            for kind, value in sorted(payload["fingerprints"].items())
        ),
    )


@dataclass(frozen=True, slots=True)
class Counts:
    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def precision(self) -> float | None:
        surfaced = self.true_positive + self.false_positive
        return self.true_positive / surfaced if surfaced else None

    @property
    def recall(self) -> float | None:
        actual = self.true_positive + self.false_negative
        return self.true_positive / actual if actual else None

    @property
    def false_positive_rate(self) -> float | None:
        negatives = self.false_positive + self.true_negative
        return self.false_positive / negatives if negatives else None

    def plus(self, surfaced: bool, same_work: bool) -> "Counts":
        return Counts(
            self.true_positive + (surfaced and same_work),
            self.false_positive + (surfaced and not same_work),
            self.true_negative + (not surfaced and not same_work),
            self.false_negative + (not surfaced and same_work),
        )


@dataclass
class Report:
    provenance: Provenance
    tight: float
    loose: float
    operating_band: Band
    overall: Counts
    per_transform: dict[str, Counts] = field(default_factory=dict)
    per_quality: dict[str, Counts] = field(default_factory=dict)

    @property
    def is_defensible(self) -> bool:
        """Whether this report can support a claim made to a user.

        Modelled data exercises the code. It says nothing about how the
        thresholds behave on photographs, and a band shown to an artist is a
        claim about photographs.
        """
        return self.provenance is Provenance.MEASURED

    def render(self) -> str:
        lines = [
            f"near-match evaluation — tight={self.tight:.3f} loose={self.loose:.3f}"
            f" operating band={self.operating_band}",
            f"data provenance: {self.provenance}"
            + ("" if self.is_defensible else "  (NOT a basis for any accuracy claim)"),
            "",
            f"  precision           {_pct(self.overall.precision)}"
            f"   ({self.overall.true_positive} true / "
            f"{self.overall.true_positive + self.overall.false_positive} surfaced)",
            f"  recall              {_pct(self.overall.recall)}",
            f"  false positive rate {_pct(self.overall.false_positive_rate)}",
            "",
            "  recall by transform",
        ]
        for transform, counts in sorted(self.per_transform.items()):
            lines.append(f"    {transform:<24} {_pct(counts.recall)}")
        lines.append("")
        lines.append("  precision and false positives by quality")
        for stratum, counts in sorted(self.per_quality.items()):
            lines.append(
                f"    {stratum:<24} precision {_pct(counts.precision)}"
                f"   fpr {_pct(counts.false_positive_rate)}"
            )
        return "\n".join(lines)


def _pct(value: float | None) -> str:
    return "     n/a" if value is None else f"{value * 100:6.1f}%"


def _stratum(quality: int) -> str:
    return "low detail" if quality < LOW_QUALITY_CEILING else "sufficient detail"


def evaluate(
    dataset: Dataset,
    tight: float = TIGHT,
    loose: float = LOOSE,
    operating_band: Band = Band.POSSIBLE,
) -> Report:
    """Score a dataset at one operating point.

    `operating_band` is the threshold at which a candidate is treated as
    surfaced to a person, which is what makes a false positive costly. Bands
    weaker than it are counted as not surfaced, matching how the alert policy
    behaves.
    """
    overall = Counts()
    per_transform: dict[str, Counts] = {}
    per_quality: dict[str, Counts] = {}

    for pair in dataset.pairs:
        band, _ = classify(pair.distances(), pair.quality(), tight=tight, loose=loose)
        surfaced = band is not None and BAND_ORDER[band] <= BAND_ORDER[operating_band]

        overall = overall.plus(surfaced, pair.same_work)
        transform = per_transform.get(pair.transform, Counts())
        per_transform[pair.transform] = transform.plus(surfaced, pair.same_work)
        stratum = _stratum(pair.quality())
        per_quality[stratum] = per_quality.get(stratum, Counts()).plus(
            surfaced, pair.same_work
        )

    return Report(
        provenance=dataset.provenance,
        tight=tight,
        loose=loose,
        operating_band=operating_band,
        overall=overall,
        per_transform=per_transform,
        per_quality=per_quality,
    )


def sweep(
    dataset: Dataset,
    tights: Sequence[float],
    looses: Sequence[float],
    operating_band: Band = Band.POSSIBLE,
) -> list[Report]:
    """Score every valid threshold combination, best precision first."""
    reports = [
        evaluate(dataset, tight, loose, operating_band)
        for tight in tights
        for loose in looses
        if tight <= loose
    ]
    if not reports:
        raise EvaluationError("no valid threshold combinations: every tight > loose")
    reports.sort(
        key=lambda r: (-(r.overall.precision or 0), -(r.overall.recall or 0))
    )
    return reports


def recommend(
    dataset: Dataset,
    tights: Sequence[float],
    looses: Sequence[float],
    minimum_precision: float = 0.95,
    operating_band: Band = Band.POSSIBLE,
) -> Report:
    """The highest-recall operating point that still meets a precision floor.

    Precision is a floor rather than something traded off, because the cost of
    a false positive is borne by a third party who did nothing. Among the
    points that clear it, more recall is free.
    """
    if not dataset.pairs:
        raise EvaluationError("cannot recommend from an empty dataset")
    if dataset.provenance is not Provenance.MEASURED:
        raise EvaluationError(
            "refusing to recommend thresholds from modelled data: it exercises"
            " the code and says nothing about real images"
        )
    qualifying = [
        report
        for report in sweep(dataset, tights, looses, operating_band)
        if (report.overall.precision or 0) >= minimum_precision
    ]
    if not qualifying:
        raise EvaluationError(
            f"no threshold reaches {minimum_precision:.0%} precision on this data;"
            " widening the search would trade accusations for coverage"
        )
    return max(qualifying, key=lambda r: (r.overall.recall or 0))


@dataclass(frozen=True, slots=True)
class Regression:
    metric: str
    baseline: float
    current: float

    def __str__(self) -> str:
        return (
            f"{self.metric}: {self.baseline * 100:.1f}% -> {self.current * 100:.1f}%"
        )


def compare(
    baseline: Report, current: Report, tolerance: float = 0.02
) -> list[Regression]:
    """Metrics that fell by more than `tolerance` between two runs.

    Run on every change to a hash, a threshold, or the banding rules. A silent
    fifteen percent drop in precision is the failure this exists to catch, and
    nothing else in the system would notice it.
    """
    if not 0 <= tolerance < 1:
        raise EvaluationError("tolerance must be between 0 and 1")

    regressions = []
    for metric in ("precision", "recall"):
        was = getattr(baseline.overall, metric)
        now = getattr(current.overall, metric)
        if was is not None and now is not None and was - now > tolerance:
            regressions.append(Regression(metric, was, now))

    for transform, counts in baseline.per_transform.items():
        was = counts.recall
        now = current.per_transform.get(transform, Counts()).recall
        if was is None:
            continue
        if now is None or was - now > tolerance:
            regressions.append(Regression(f"recall[{transform}]", was, now or 0.0))

    for stratum, counts in baseline.per_quality.items():
        was = counts.precision
        now = current.per_quality.get(stratum, Counts()).precision
        if was is None:
            continue
        if now is None or was - now > tolerance:
            regressions.append(Regression(f"precision[{stratum}]", was, now or 0.0))

    return regressions
