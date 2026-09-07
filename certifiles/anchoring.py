"""Anchors: bounding how far back the log could be dated.

Anchors publish a tree head somewhere the operator does not control, so a
record cannot later be claimed to be older than the anchor that already covered
it. ADR 0001 requires them at every stage, including stage 0 where there are no
witnesses at all, because they need no counterparty to agree to anything.

What an anchor is not: a witness. A timestamping authority will happily stamp
two divergent tree heads without noticing, so anchors bound backdating and do
nothing about a fork. They never count toward K, and there is deliberately no
function here that would let them.

Two clocks, and only one is evidence:

- `claimed_at` is when this service says it submitted. The operator controls it,
  so it carries no weight — the same reasoning that keeps a self-asserted
  registration time out of a record.
- `attested_at` comes from the receipt itself: a Bitcoin block time, a TSA
  token's genTime. That is the number a backdating bound may rest on, and it is
  None until the anchor confirms.

Submitting is network work and lives behind the `Anchor` protocol so a KMS-like
boundary applies: this module holds the ledger of receipts and the reasoning
over them, and knows nothing about how any particular anchor talks to the world.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Iterable, Protocol, Sequence

from certifiles.checkpoint import Checkpoint

DEFAULT_INTERVAL_SECONDS = 3600
# ADR 0001: a log that stops publishing is withholding, and withholding is
# indistinguishable from an attack in progress.
STALENESS_INTERVALS = 3


class AnchorError(RuntimeError):
    """The anchor ledger refused an operation."""


class AnchorKind(StrEnum):
    OPENTIMESTAMPS = "opentimestamps"
    RFC3161 = "rfc3161"
    OBJECT_LOCK = "object_lock"


@dataclass(frozen=True, slots=True)
class AnchorReceipt:
    kind: AnchorKind
    checkpoint_size: int
    checkpoint_root: bytes
    claimed_at: int
    receipt: bytes
    attested_at: int | None = None

    def __post_init__(self) -> None:
        if self.checkpoint_size < 0:
            raise AnchorError("checkpoint size must not be negative")
        if len(self.checkpoint_root) != 32:
            raise AnchorError("checkpoint root must be 32 bytes")
        if self.attested_at is not None and self.attested_at < 0:
            raise AnchorError("attested time must not be negative")

    @property
    def is_evidence(self) -> bool:
        """Whether this receipt can bound anything.

        An unconfirmed receipt proves only that we say we submitted it.
        """
        return self.attested_at is not None


class Anchor(Protocol):
    """Publishes a tree head somewhere the operator cannot rewrite."""

    @property
    def kind(self) -> AnchorKind: ...

    def submit(self, checkpoint: Checkpoint, now: int) -> AnchorReceipt: ...

    def confirm(self, receipt: AnchorReceipt) -> AnchorReceipt: ...


SCHEMA = """
CREATE TABLE IF NOT EXISTS anchors (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    kind           TEXT NOT NULL,
    checkpoint_size INTEGER NOT NULL,
    checkpoint_root BLOB NOT NULL,
    claimed_at     INTEGER NOT NULL,
    attested_at    INTEGER,
    receipt        BLOB NOT NULL
);

CREATE INDEX IF NOT EXISTS anchors_by_size ON anchors (checkpoint_size);

CREATE TRIGGER IF NOT EXISTS anchors_are_not_deletable
BEFORE DELETE ON anchors
BEGIN
    SELECT RAISE(ABORT, 'anchor receipts are append-only');
END;

-- Confirmation is the one legitimate update: an OpenTimestamps receipt is
-- upgraded when its Bitcoin transaction confirms. Nothing else may change,
-- and an attested time may never be rewritten once set.
CREATE TRIGGER IF NOT EXISTS anchors_only_confirm
BEFORE UPDATE ON anchors
BEGIN
    SELECT RAISE(ABORT, 'only attested_at and receipt may be set, once')
    WHERE OLD.kind <> NEW.kind
       OR OLD.checkpoint_size <> NEW.checkpoint_size
       OR OLD.checkpoint_root <> NEW.checkpoint_root
       OR OLD.claimed_at <> NEW.claimed_at
       OR OLD.attested_at IS NOT NULL;
END;
"""


class AnchorLedger:
    """Receipts, and the reasoning over them."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(str(path), isolation_level=None)
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "AnchorLedger":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def record(self, receipt: AnchorReceipt) -> None:
        self._connection.execute(
            "INSERT INTO anchors (kind, checkpoint_size, checkpoint_root,"
            " claimed_at, attested_at, receipt) VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(receipt.kind),
                receipt.checkpoint_size,
                receipt.checkpoint_root,
                receipt.claimed_at,
                receipt.attested_at,
                receipt.receipt,
            ),
        )

    def confirm(self, receipt: AnchorReceipt) -> None:
        """Attach an attested time to a receipt that had none."""
        if receipt.attested_at is None:
            raise AnchorError("confirmation requires an attested time")
        cursor = self._connection.execute(
            "UPDATE anchors SET attested_at = ?, receipt = ? WHERE kind = ?"
            " AND checkpoint_size = ? AND checkpoint_root = ? AND attested_at IS NULL",
            (
                receipt.attested_at,
                receipt.receipt,
                str(receipt.kind),
                receipt.checkpoint_size,
                receipt.checkpoint_root,
            ),
        )
        if cursor.rowcount == 0:
            raise AnchorError("no unconfirmed receipt matches this checkpoint")

    def all(self) -> list[AnchorReceipt]:
        rows = self._connection.execute(
            "SELECT kind, checkpoint_size, checkpoint_root, claimed_at, receipt,"
            " attested_at FROM anchors ORDER BY checkpoint_size, id"
        )
        return [
            AnchorReceipt(AnchorKind(r[0]), r[1], r[2], r[3], r[4], r[5]) for r in rows
        ]


def evidence_only(receipts: Iterable[AnchorReceipt]) -> list[AnchorReceipt]:
    return [r for r in receipts if r.is_evidence]


def backdating_bound(
    receipts: Iterable[AnchorReceipt], position: int, root_at=None
) -> AnchorReceipt | None:
    """The earliest attested anchor proving the entry at `position` already existed.

    An anchor over a tree of size S covers positions 0 to S-1 and says nothing
    about anything later, so the bound is the earliest attested receipt whose
    size is strictly greater than the position. Getting the comparison wrong by
    one would claim an anchor covers a record entered after it, which is exactly
    the backdating this is meant to prevent.

    None means the entry is anchored by nothing yet, which is a real state and
    must be reported rather than treated as unbounded-but-fine.

    Pass `root_at` — TransparencyLog.root satisfies it — and receipts whose root
    the log does not hold are excluded. Without it a receipt for a history that
    never existed still produces a bound, which is a bound resting on nothing.
    Callers that hold a log should always pass it.
    """
    if position < 0:
        raise AnchorError("position must not be negative")
    usable = evidence_only(receipts)
    if root_at is not None:
        mismatched = {id(r) for r in diverged(usable, root_at)}
        usable = [r for r in usable if id(r) not in mismatched]
    covering = [r for r in usable if r.checkpoint_size > position]
    if not covering:
        return None
    return min(covering, key=lambda r: (r.attested_at, r.checkpoint_size))


def latest_attested(receipts: Iterable[AnchorReceipt]) -> AnchorReceipt | None:
    attested = evidence_only(receipts)
    return max(attested, key=lambda r: r.attested_at) if attested else None


def is_stale(
    receipts: Iterable[AnchorReceipt],
    now: int,
    interval_seconds: int = DEFAULT_INTERVAL_SECONDS,
    intervals: int = STALENESS_INTERVALS,
) -> bool:
    """Whether anchoring has stopped for longer than the tolerated window.

    A log with no attested anchor at all is stale by definition — there is
    nothing bounding it, and treating that as fresh would let a log that never
    anchored look identical to one that anchors reliably.
    """
    if interval_seconds <= 0 or intervals <= 0:
        raise AnchorError("interval and intervals must be positive")
    newest = latest_attested(receipts)
    if newest is None:
        return True
    return now - newest.attested_at > interval_seconds * intervals


def due_at(
    receipts: Iterable[AnchorReceipt], interval_seconds: int = DEFAULT_INTERVAL_SECONDS
) -> int:
    """When the next anchor should be submitted.

    Measured from the claimed submission time rather than the attested one: the
    schedule is an operational matter, and an anchor that has not confirmed yet
    should not cause a second submission of the same window.
    """
    if interval_seconds <= 0:
        raise AnchorError("interval must be positive")
    rows = list(receipts)
    if not rows:
        return 0
    return max(r.claimed_at for r in rows) + interval_seconds


def diverged(receipts: Iterable[AnchorReceipt], root_at) -> list[AnchorReceipt]:
    """Anchors whose root disagrees with the log's own root at that size.

    A mismatch is not a bookkeeping error. It means the log published one
    history to the outside world and holds another now, which is the split-view
    evidence the whole design exists to make detectable. `root_at` takes a size
    and returns that tree's root — TransparencyLog.root satisfies it.
    """
    mismatched = []
    for receipt in receipts:
        try:
            actual = root_at(receipt.checkpoint_size)
        except Exception:
            # A size the log can no longer produce is itself a divergence: the
            # log has shrunk below something it already published.
            mismatched.append(receipt)
            continue
        if actual != receipt.checkpoint_root:
            mismatched.append(receipt)
    return mismatched


class DirectoryAnchor:
    """Writes tree heads to a directory. For development, not for production.

    Included because the object-lock anchor has this shape, and because the
    ledger needs something to exercise. It attests no time of its own — a file
    this process wrote proves only that this process wrote it — so `attested_at`
    stays None and it can never become evidence. That is the honest behaviour,
    and it means a development setup cannot accidentally look anchored.
    """

    kind = AnchorKind.OBJECT_LOCK

    def __init__(self, directory: str | Path) -> None:
        self._directory = Path(directory)
        self._directory.mkdir(parents=True, exist_ok=True)

    def submit(self, checkpoint: Checkpoint, now: int) -> AnchorReceipt:
        body = checkpoint.body()
        target = self._directory / f"{checkpoint.size:012d}.checkpoint"
        if target.exists() and target.read_bytes() != body:
            raise AnchorError(
                f"a different tree head is already anchored at size"
                f" {checkpoint.size}: the log has diverged from what it published"
            )
        target.write_bytes(body)
        return AnchorReceipt(
            kind=self.kind,
            checkpoint_size=checkpoint.size,
            checkpoint_root=checkpoint.root_hash,
            claimed_at=now,
            receipt=body,
            attested_at=None,
        )

    def confirm(self, receipt: AnchorReceipt) -> AnchorReceipt:
        raise AnchorError(
            "a directory anchor cannot attest a time; use OpenTimestamps or a TSA"
        )
