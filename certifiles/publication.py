"""Publishing the log as static files.

Verification must not depend on Certifiles being reachable, solvent, or
honest. Everything a verifier needs is written here as plain files that can sit
behind any static host or object store, so a browser or the CLI can check a
record with no API in the path — and so the records outlive the company, which
is the answer to the loudest objection a provenance service faces.

The layout is the contract. A verifier written in another language reads these
paths and these bytes, so changing either invalidates work already published;
`FORMAT_VERSION` exists to make that a migration rather than a surprise.

    manifest.json                     what this publication is, and its format
    checkpoint                        the latest signed tree head
    checkpoints/<size>                every signed tree head, kept forever
    entries/<sharded>.json            one record's canonical leaf bytes
    proofs/inclusion/<sharded>.json   that record's proof, against a fixed size
    proofs/consistency/<a>-<b>.json   a published head is a prefix of a later one
    anchors/<size>.json               receipts covering that head
    index/by-content/<sharded>.json   fingerprint to positions

Two classes of file, and the difference is load-bearing.

**Immutable**: entries, inclusion proofs against a stated size, and consistency
proofs. Once published they are never rewritten, and `publish` refuses to
overwrite one whose bytes would change rather than quietly republishing
history.

**Append-only**: historical checkpoints and anchors. Their *content* is fixed —
a tree head's body, an anchor's root and attested time — but signatures and
confirmations accumulate on them. ADR 0001 raises a record's assurance when a
witnessed head covers it, which means republishing the same head with a
cosignature added, so treating the serialized bytes as immutable would make
that lifecycle unreachable. A signature may be added and never removed; an
attested time may be set once and never moved.

**Mutable**: the manifest, the latest checkpoint pointer, and the content
index, which grows as new claims on a fingerprint arrive.

The index is a convenience and never evidence. A verifier that trusts it can be
told a record does not exist — an operator can omit an entry from an index it
writes. What an index cannot do is invent a record, because the proof is what
is checked. The defence against omission is that the whole log is published:
anyone can rebuild the index from `entries/` and see what is missing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Sequence

from certifiles.anchoring import AnchorReceipt, diverged
from certifiles.checkpoint import SignedCheckpoint, parse as parse_checkpoint
from certifiles.record import SHA256_PATTERN

FORMAT_VERSION = 1


class PublicationError(RuntimeError):
    """Publishing refused. Never raised for an unchanged republication."""


@dataclass
class PublishReport:
    written: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    size: int = 0

    def __str__(self) -> str:
        return (
            f"published size {self.size}: {len(self.written)} written,"
            f" {len(self.unchanged)} already current"
        )


def _sharded(position: int) -> str:
    """A twelve-digit position split three ways.

    Flat directories of millions of files are miserable on most filesystems and
    on some object stores' listing APIs. Three levels keeps any one directory
    under ten thousand entries up to a trillion records.
    """
    if position < 0:
        raise PublicationError("position must not be negative")
    padded = f"{position:012d}"
    return f"{padded[:4]}/{padded[4:8]}/{padded[8:]}"


def _sharded_hash(content_hash: str) -> str:
    """Shard a fingerprint into a path.

    The value is validated, not merely length-checked: it becomes a filesystem
    path, and once an HTTP verify endpoint passes a user-supplied hash through
    here an unvalidated one is an arbitrary-file read.
    """
    if not isinstance(content_hash, str) or not SHA256_PATTERN.match(content_hash):
        raise PublicationError(
            "content hash must be 64 lowercase hex characters to be used as a path"
        )
    return f"{content_hash[:2]}/{content_hash[2:4]}/{content_hash}"


def _anchor_identity(anchor: dict) -> tuple:
    """What makes two receipts the same receipt, ignoring confirmation state."""
    return (anchor["kind"], anchor["checkpoint_size"], anchor["checkpoint_root"])


class StaticPublication:
    def __init__(self, root: str | Path) -> None:
        self.root = Path(root)

    # ---- file handling -------------------------------------------------

    def _write(self, relative: str, data: bytes, immutable: bool) -> str | None:
        """Write a file. Returns the path if written, None if already current.

        An immutable file whose content would change is refused rather than
        overwritten. Republishing is routine — a scheduled run rewrites the same
        entries — so silently accepting a changed byte would turn a bug, or a
        rewrite of history, into an ordinary-looking successful run.
        """
        target = self.root / relative
        if target.exists():
            existing = target.read_bytes()
            if existing == data:
                return None
            if immutable:
                raise PublicationError(
                    f"{relative} is already published with different content."
                    " Published history is not rewritten; investigate before"
                    " republishing."
                )
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        return relative

    def _write_json(self, relative: str, payload: dict, immutable: bool) -> str | None:
        data = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return self._write(relative, data, immutable)

    def _published_size(self) -> int | None:
        target = self.root / "manifest.json"
        if not target.exists():
            return None
        try:
            return json.loads(target.read_text())["size"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PublicationError(
                "manifest.json is present but unreadable; the site is in an"
                " unknown state and must be inspected before republishing"
            ) from exc

    def _record(self, report: PublishReport, result: str | None, relative: str) -> None:
        (report.written if result else report.unchanged).append(relative)

    # ---- publishing ----------------------------------------------------

    def publish(
        self,
        log,
        signed: SignedCheckpoint,
        anchors: Sequence[AnchorReceipt] = (),
        previous_sizes: Sequence[int] = (),
    ) -> PublishReport:
        """Write everything a verifier needs for the log at `signed`'s size.

        `signed` is supplied rather than produced here: signing lives behind the
        signer boundary, and a publisher with a key would defeat the point of
        having one.
        """
        size = signed.checkpoint.size
        if size > log.size():
            raise PublicationError(
                f"checkpoint claims size {size} but the log holds {log.size()}"
            )
        if signed.checkpoint.root_hash != log.root(size):
            raise PublicationError(
                "checkpoint root does not match the log at that size; refusing to"
                " publish a head the log cannot support"
            )

        # Anchors are the backdating bound precisely because they sit outside
        # operator control. Publishing one the log cannot support hands that
        # control back, and diverged() already knows how to spot it.
        mismatched = diverged(anchors, log.root)
        if mismatched:
            raise PublicationError(
                f"{len(mismatched)} anchor(s) reference a tree head this log does"
                " not hold. That is divergence evidence, not a publishing error."
            )

        published_size = self._published_size()
        if published_size is not None and size < published_size:
            raise PublicationError(
                f"refusing to move the published head backwards from"
                f" {published_size} to {size}: entries and proofs for the newer"
                " head remain on the site, and a witness may already have"
                " advanced past it."
            )

        report = PublishReport(size=size)
        self._publish_checkpoint(report, signed)
        self._publish_entries(report, log, size)
        self._publish_consistency(report, log, size, previous_sizes)
        self._publish_anchors(report, anchors, size)
        self._publish_manifest(report, signed, anchors)
        return report

    def _publish_checkpoint(self, report: PublishReport, signed: SignedCheckpoint) -> None:
        """Publish a tree head, allowing signatures to accumulate on it.

        Immutability applies to the *body* — origin, size and root — because a
        change there is the split-view evidence the design exists to surface.
        The signature block is deliberately mutable in one direction: ADR 0001
        issues records as PENDING_WITNESS and raises their assurance when a
        witnessed head covers them, which means republishing the same head with
        a cosignature added. Treating the serialized bytes as immutable made
        that lifecycle unreachable, and the only workaround was deleting the
        published file — the exact rewrite the check exists to prevent.
        """
        data = signed.serialize()
        size = signed.checkpoint.size
        historical = f"checkpoints/{size:012d}"
        existing = self.root / historical

        if existing.exists():
            try:
                published = parse_checkpoint(existing.read_bytes())
            except Exception as exc:
                raise PublicationError(
                    f"{historical} is already published but cannot be parsed;"
                    " investigate before republishing"
                ) from exc
            if published.checkpoint.body() != signed.checkpoint.body():
                raise PublicationError(
                    f"{historical} is already published with a different tree head."
                    " Published history is not rewritten; this is split-view"
                    " evidence, not a publishing error."
                )
            was = {(s.key_name, s.key_hash, s.signature) for s in published.signatures}
            now = {(s.key_name, s.key_hash, s.signature) for s in signed.signatures}
            if not was <= now:
                raise PublicationError(
                    f"{historical} would lose {len(was - now)} already-published"
                    " signature(s). Assurance is never revised downward silently."
                )

        self._record(report, self._write(historical, data, immutable=False), historical)
        # The latest pointer is the one file that legitimately changes.
        self._record(report, self._write("checkpoint", data, immutable=False), "checkpoint")

    def _publish_entries(self, report: PublishReport, log, size: int) -> None:
        for position in range(size):
            entry = log.entry(position)
            if entry is None:
                raise PublicationError(f"log is missing position {position}")

            path = f"entries/{_sharded(position)}.json"
            self._record(
                report,
                self._write_json(
                    path,
                    {
                        "position": position,
                        "leaf": entry.leaf_data.decode("utf-8"),
                        "leaf_hash": entry.leaf_hash.hex(),
                    },
                    immutable=True,
                ),
                path,
            )

            proof_path = f"proofs/inclusion/{_sharded(position)}.json"
            if not (self.root / proof_path).exists():
                # Proofs are relative to a tree size, so one is published per
                # entry against the first head that covered it and never
                # recomputed. A verifier reaches a later head through the
                # consistency proofs rather than through a reissued proof.
                proof = log.inclusion_proof(position, size=size)
                self._record(
                    report,
                    self._write_json(
                        proof_path,
                        {
                            "position": position,
                            "tree_size": size,
                            "proof": [node.hex() for node in proof],
                        },
                        immutable=True,
                    ),
                    proof_path,
                )
            else:
                report.unchanged.append(proof_path)

            index_path = f"index/by-content/{_sharded_hash(entry.content_hash)}.json"
            self._append_to_index(report, index_path, entry.content_hash, position)

    def _append_to_index(
        self, report: PublishReport, path: str, content_hash: str, position: int
    ) -> None:
        target = self.root / path
        positions = []
        if target.exists():
            try:
                positions = json.loads(target.read_text())["positions"]
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                raise PublicationError(
                    f"{path} is published but unreadable, most likely a truncated"
                    " write from an interrupted run; repair or remove it"
                ) from exc
        if position in positions:
            report.unchanged.append(path)
            return
        positions = sorted(positions + [position])
        self._record(
            report,
            self._write_json(
                path,
                {"content_hash": content_hash, "positions": positions},
                immutable=False,
            ),
            path,
        )

    def _publish_consistency(
        self, report: PublishReport, log, size: int, previous_sizes: Sequence[int]
    ) -> None:
        for previous in previous_sizes:
            if not 0 < previous < size:
                continue
            path = f"proofs/consistency/{previous:012d}-{size:012d}.json"
            proof = log.consistency_proof(previous, size=size)
            self._record(
                report,
                self._write_json(
                    path,
                    {
                        "from_size": previous,
                        "to_size": size,
                        "proof": [node.hex() for node in proof],
                    },
                    immutable=True,
                ),
                path,
            )

    def _publish_anchors(
        self, report: PublishReport, anchors: Sequence[AnchorReceipt], size: int
    ) -> None:
        """Publish anchor receipts additively.

        Rewriting this file was a way to move a backdating bound earlier: a
        later run could replace an honest receipt with one attesting a smaller
        time, and the manifest would follow it. A receipt may gain a
        confirmation and may never be removed or moved earlier.
        """
        by_size: dict[int, list[dict]] = {}
        for anchor in anchors:
            by_size.setdefault(anchor.checkpoint_size, []).append(
                {
                    "kind": str(anchor.kind),
                    "checkpoint_size": anchor.checkpoint_size,
                    "checkpoint_root": anchor.checkpoint_root.hex(),
                    "claimed_at": anchor.claimed_at,
                    "attested_at": anchor.attested_at,
                    "receipt": anchor.receipt.hex(),
                }
            )
        for anchor_size, entries in by_size.items():
            path = f"anchors/{anchor_size:012d}.json"
            merged = self._merge_anchors(path, entries)
            self._record(
                report,
                self._write_json(
                    path,
                    {"checkpoint_size": anchor_size, "anchors": merged},
                    immutable=False,
                ),
                path,
            )

    def _merge_anchors(self, path: str, incoming: list[dict]) -> list[dict]:
        target = self.root / path
        if not target.exists():
            return sorted(incoming, key=_anchor_identity)
        try:
            published = json.loads(target.read_text())["anchors"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PublicationError(
                f"{path} is published but unreadable; repair or remove it"
            ) from exc

        merged = {_anchor_identity(a): a for a in published}
        for anchor in incoming:
            identity = _anchor_identity(anchor)
            existing = merged.get(identity)
            if existing is None:
                merged[identity] = anchor
                continue
            was, now = existing["attested_at"], anchor["attested_at"]
            if was is not None and now != was:
                raise PublicationError(
                    f"{path} would change an attested time from {was} to {now}."
                    " An anchor's attestation is set once; moving it is the"
                    " backdating anchors exist to prevent."
                )
            if was is None and now is not None:
                merged[identity] = anchor
        return [merged[key] for key in sorted(merged)]

    def _publish_manifest(
        self,
        report: PublishReport,
        signed: SignedCheckpoint,
        anchors: Sequence[AnchorReceipt],
    ) -> None:
        attested = [a.attested_at for a in anchors if a.attested_at is not None]
        payload = {
            "format_version": FORMAT_VERSION,
            "origin": signed.checkpoint.origin,
            "size": signed.checkpoint.size,
            "root_hash": signed.checkpoint.root_hash.hex(),
            "signature_count": len(signed.signatures),
            "latest_attested_anchor": max(attested) if attested else None,
            "layout": {
                "checkpoint": "checkpoint",
                "checkpoints": "checkpoints/{size:012d}",
                "entries": "entries/{position:012d sharded 4/4/4}.json",
                "inclusion_proofs": "proofs/inclusion/{position sharded}.json",
                "consistency_proofs": "proofs/consistency/{from}-{to}.json",
                "anchors": "anchors/{size:012d}.json",
                "content_index": "index/by-content/{hash sharded 2/2}.json",
            },
            "notice": (
                "The index is a convenience and is not evidence. A record is"
                " proven by its entry, its inclusion proof and a signed"
                " checkpoint, all of which are published here."
            ),
        }
        self._record(
            report, self._write_json("manifest.json", payload, immutable=False),
            "manifest.json",
        )

    # ---- reading back --------------------------------------------------

    def positions_for(self, content_hash: str) -> list[int]:
        """Positions claiming a fingerprint, from the published index."""
        target = self.root / f"index/by-content/{_sharded_hash(content_hash)}.json"
        if not target.exists():
            return []
        try:
            return json.loads(target.read_text())["positions"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise PublicationError(
                f"the published index for {content_hash[:16]} is unreadable"
            ) from exc

    def inclusion_proof(self, position: int) -> dict | None:
        target = self.root / f"proofs/inclusion/{_sharded(position)}.json"
        return json.loads(target.read_text()) if target.exists() else None

    def entry(self, position: int) -> dict | None:
        target = self.root / f"entries/{_sharded(position)}.json"
        return json.loads(target.read_text()) if target.exists() else None

    def latest_checkpoint(self) -> bytes | None:
        target = self.root / "checkpoint"
        return target.read_bytes() if target.exists() else None
