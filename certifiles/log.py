"""The append-only transparency log.

This is the thing ADR 0001 is about. Everything else in the service reads from
here: the public verify page, the record permalink, and near-match monitoring.

Two properties matter more than any feature:

- **Positions are gapless and never reassigned.** A record's position is its
  place in history, and priority in an ownership dispute is decided by it.
- **Nothing is ever updated or deleted.** Enforced by database triggers rather
  than by convention, so an application bug cannot quietly rewrite history.

Be clear about what that enforcement is worth. Triggers stop this program from
rewriting the log; they do not stop whoever holds the database file, and the
operator holds it. Only external witnessing constrains the operator, which is
why the threat model puts witnessing before the first production record and
not after.

Duplicate fingerprints are accepted rather than rejected. The log records
claims, and refusing a second claim on a hash would let the first registrant of
a widely held file block everyone else permanently. Priority is expressed by
position: `claims_for` returns every claim in order, earliest first.
"""

from __future__ import annotations

import sqlite3
import threading
from dataclasses import dataclass
from pathlib import Path

from certifiles.checkpoint import Checkpoint
from certifiles.merkle import consistency_proof, inclusion_proof, leaf_hash, root_hash
from certifiles.record import Record, validate

SCHEMA = """
CREATE TABLE IF NOT EXISTS records (
    position     INTEGER PRIMARY KEY,
    leaf_hash    BLOB NOT NULL,
    leaf_data    BLOB NOT NULL,
    content_hash TEXT NOT NULL,
    identity_id  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS records_by_content ON records (content_hash, position);
CREATE INDEX IF NOT EXISTS records_by_identity ON records (identity_id, position);

CREATE TRIGGER IF NOT EXISTS records_are_append_only_update
BEFORE UPDATE ON records
BEGIN
    SELECT RAISE(ABORT, 'records are append-only');
END;

CREATE TRIGGER IF NOT EXISTS records_are_append_only_delete
BEFORE DELETE ON records
BEGIN
    SELECT RAISE(ABORT, 'records are append-only');
END;
"""

# Proofs are computed from every leaf hash in the log. That is honest and
# correct, and it is linear in log size. Measured on commodity hardware it stays
# under a few hundred milliseconds to roughly this many records, which is well
# past where witness recruitment becomes the binding constraint. Replace with an
# incremental tree before it matters, not before it is measured.
LINEAR_SCAN_ADVISORY_LIMIT = 100_000


class LogError(RuntimeError):
    """The log refused an operation. Never raised for ordinary lookups."""


@dataclass(frozen=True, slots=True)
class LogEntry:
    position: int
    leaf_hash: bytes
    leaf_data: bytes
    content_hash: str
    identity_id: str


class TransparencyLog:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.execute("PRAGMA foreign_keys=ON")
        # Statement-level serialisation does not make a multi-statement
        # transaction atomic against another thread's. append() holds this for
        # the whole read-size-then-insert sequence, which is what stops two
        # concurrent writers computing the same position.
        self._write_lock = threading.Lock()
        self._connection.executescript(SCHEMA)
        self.check_integrity()

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "TransparencyLog":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    # ---- writing -------------------------------------------------------

    def append(self, record: Record) -> LogEntry:
        """Add a record and return its permanent position.

        Validates first: leaf_data() refuses an invalid record, and the one
        place bad input must never reach is the log.

        The explicit call is redundant while leaf_data() validates — mutation
        testing confirmed removing it changes no outcome. Kept so the write path
        states its own precondition rather than inheriting it from a serializer.
        """
        validate(record)
        data = record.leaf_data()
        digest = leaf_hash(data)

        # BEGIN IMMEDIATE takes the write lock before the size is read, so a
        # second writer cannot compute the same position from a stale read.
        # What actually makes a collision impossible is the PRIMARY KEY on
        # position — mutation testing showed a deferred BEGIN still fails,
        # because the duplicate insert is refused rather than silently applied.
        # IMMEDIATE turns that late, confusing failure into no contention at
        # all, which is why it stays.
        with self._write_lock:
            return self._append_locked(record, data, digest)

    def _append_locked(self, record: Record, data: bytes, digest: bytes) -> LogEntry:
        self._connection.execute("BEGIN IMMEDIATE")
        try:
            row = self._connection.execute(
                "SELECT COALESCE(MAX(position) + 1, 0) FROM records"
            ).fetchone()
            position = row[0]
            self._connection.execute(
                "INSERT INTO records (position, leaf_hash, leaf_data, content_hash,"
                " identity_id) VALUES (?, ?, ?, ?, ?)",
                (
                    position,
                    digest,
                    data,
                    record.content.sha256,
                    record.issuer.identity_id,
                ),
            )
            self._connection.execute("COMMIT")
        except Exception:
            self._connection.execute("ROLLBACK")
            raise

        return LogEntry(
            position=position,
            leaf_hash=digest,
            leaf_data=data,
            content_hash=record.content.sha256,
            identity_id=record.issuer.identity_id,
        )

    # ---- reading -------------------------------------------------------

    def size(self) -> int:
        """One past the highest position, which for a gapless log is the count.

        Derived from MAX(position) rather than COUNT(*) so it agrees with how a
        position is assigned. check_integrity() is what asserts the two match.
        """
        row = self._connection.execute(
            "SELECT COALESCE(MAX(position) + 1, 0) FROM records"
        ).fetchone()
        return row[0]

    def check_integrity(self) -> None:
        """Verify positions are gapless, raising rather than serving bad proofs.

        The append-only triggers stop this program from opening a gap. They do
        not stop whoever holds the database file, and a gap is worse than a
        visible failure: every leaf after it shifts, so the log would emit
        proofs against a root no honest history could produce. Cheap to check,
        so it runs on open and can be run again before publishing.
        """
        count, highest = self._connection.execute(
            "SELECT COUNT(*), COALESCE(MAX(position) + 1, 0) FROM records"
        ).fetchone()
        if count != highest:
            raise LogError(
                f"log is not contiguous: {count} records but highest position"
                f" implies {highest}. History has been altered outside this code."
            )

    def _leaves(self, upto: int | None = None) -> list[bytes]:
        expected = self.size() if upto is None else upto
        if upto is None:
            rows = self._connection.execute(
                "SELECT leaf_hash FROM records ORDER BY position"
            )
        else:
            rows = self._connection.execute(
                "SELECT leaf_hash FROM records WHERE position < ? ORDER BY position",
                (upto,),
            )
        leaves = [row[0] for row in rows]
        if len(leaves) != expected:
            # Caught here rather than in the caller because this is the exact
            # point where a missing leaf would become a wrong proof.
            raise LogError(
                f"expected {expected} leaves, found {len(leaves)}: the log is not"
                " contiguous and any proof from it would be wrong"
            )
        return leaves

    def root(self, size: int | None = None) -> bytes:
        """Merkle root over the first `size` entries, or the whole log."""
        if size is None:
            return root_hash(self._leaves())
        if not 0 <= size <= self.size():
            raise LogError(f"size {size} outside 0..{self.size()}")
        return root_hash(self._leaves(upto=size))

    def entry(self, position: int) -> LogEntry | None:
        row = self._connection.execute(
            "SELECT position, leaf_hash, leaf_data, content_hash, identity_id"
            " FROM records WHERE position = ?",
            (position,),
        ).fetchone()
        return LogEntry(*row) if row else None

    def claims_for(self, content_hash: str) -> list[LogEntry]:
        """Every claim on a fingerprint, earliest first.

        A list rather than a single record, deliberately. Duplicates are
        accepted, so the caller must decide what to show — and the honest answer
        is usually "first registered by X, also claimed by Y", not a winner.
        """
        rows = self._connection.execute(
            "SELECT position, leaf_hash, leaf_data, content_hash, identity_id"
            " FROM records WHERE content_hash = ? ORDER BY position",
            (content_hash,),
        )
        return [LogEntry(*row) for row in rows]

    def claims_by(self, identity_id: str) -> list[LogEntry]:
        rows = self._connection.execute(
            "SELECT position, leaf_hash, leaf_data, content_hash, identity_id"
            " FROM records WHERE identity_id = ? ORDER BY position",
            (identity_id,),
        )
        return [LogEntry(*row) for row in rows]

    # ---- proofs --------------------------------------------------------

    def inclusion_proof(self, position: int, size: int | None = None) -> list[bytes]:
        """Proof that the entry at `position` is in the tree of `size`."""
        tree_size = self.size() if size is None else size
        if not 0 <= position < tree_size:
            raise LogError(f"position {position} outside a tree of size {tree_size}")
        return inclusion_proof(self._leaves(upto=tree_size), position)

    def consistency_proof(self, old_size: int, size: int | None = None) -> list[bytes]:
        """Proof that the tree of `old_size` is a prefix of the tree of `size`.

        This is what a witness checks before cosigning, and a failure from its
        verifier is the COMPROMISED outcome rather than an error.
        """
        tree_size = self.size() if size is None else size
        if not 0 < old_size <= tree_size:
            raise LogError(f"old_size {old_size} outside 1..{tree_size}")
        return consistency_proof(self._leaves(upto=tree_size), old_size)

    # ---- checkpoints ---------------------------------------------------

    def checkpoint(self, origin: str, size: int | None = None) -> Checkpoint:
        """The unsigned tree head for `size`.

        Unsigned on purpose. Signing lives behind the signer boundary so the
        production signer can call a KMS that never releases key material; the
        log has no business holding a key.
        """
        tree_size = self.size() if size is None else size
        return Checkpoint(
            origin=origin,
            size=tree_size,
            root_hash=self.root(tree_size),
        )
