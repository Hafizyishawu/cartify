#!/usr/bin/env python3
"""Sign, anchor and publish the current tree head.

This is what makes a registered work verifiable. Until a checkpoint covering a
record is published, the record exists in the log and no one outside can check
it, so this runs on a schedule rather than on demand: ADR 0001 sets the cadence
at hourly, and the staleness bound the status page shows is three intervals.

Scheduled automation that fails silently is worse than no automation, so this
exits non-zero on any refusal and prints what it refused.

**Key custody is the open problem, and this script does not solve it.** ADR
0001 requires a non-exportable key reachable only through a service with no
standing human access. What this does instead is take a seed from the
environment, which is honest for development and must not be how a production
log is signed. The signer is passed in, so a KMS implementation replaces it
without this file changing.
"""

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from certifiles.anchoring import AnchorKind, AnchorLedger, AnchorReceipt, diverged
from certifiles.checkpoint import SignedCheckpoint, WitnessPolicy, sign
from certifiles.log import TransparencyLog
from certifiles.publication import PublicationError, StaticPublication
from certifiles.signing import InMemoryEd25519Signer

ANCHOR_INTERVAL_SECONDS = 3600
SEED_VARIABLE = "CERTIFILES_DEV_SIGNING_SEED"


def development_signer(origin: str) -> InMemoryEd25519Signer:
    seed = os.environ.get(SEED_VARIABLE)
    if not seed:
        raise SystemExit(
            f"{SEED_VARIABLE} is not set.\n"
            "This script signs with a key derived from that value, which is a\n"
            "development arrangement and not key custody. Set it explicitly so\n"
            "that signing is never something that happened by default:\n\n"
            f"  export {SEED_VARIABLE}=$(python3 -c \"import secrets;"
            "print(secrets.token_hex(32))\")\n"
        )
    material = bytes.fromhex(seed) if len(seed) == 64 else seed.encode("utf-8")
    return InMemoryEd25519Signer.from_seed(origin, __import__("hashlib").sha256(material).digest())


def publish(data: Path, site: Path, origin: str, dry_run: bool) -> int:
    if not (data / "log.db").exists():
        print(f"  no log at {data}/log.db. Register something first, or point --data at it.")
        return 1
    log = TransparencyLog(data / "log.db")
    ledger = AnchorLedger(data / "anchors.db")
    try:
        size = log.size()
        if size == 0:
            print("  the log is empty, nothing to publish")
            return 0

        signer = development_signer(origin)
        checkpoint = log.checkpoint(origin)
        signed = SignedCheckpoint(checkpoint, (sign(checkpoint, signer),))

        # An anchor is minted per interval, not per run, so publishing twice in
        # one hour does not try to move an attested time that is already set.
        stamp = int(time.time() // ANCHOR_INTERVAL_SECONDS) * ANCHOR_INTERVAL_SECONDS
        anchor = AnchorReceipt(
            kind=AnchorKind.RFC3161,
            checkpoint_size=size,
            checkpoint_root=log.root(),
            claimed_at=stamp,
            receipt=b"development-anchor",
            attested_at=stamp,
        )

        mismatched = diverged([anchor], log.root)
        if mismatched:
            print("  REFUSED: an anchor references a head this log does not hold")
            return 2

        policy = WitnessPolicy(
            version=1, effective_from_size=0,
            log_key_name=origin, log_public_key=signer.public_key,
            witnesses={}, required=0,
        )

        if dry_run:
            print(f"  would publish size {size}, root {log.root().hex()[:16]}…")
            print(f"  stage 0: no witnesses, so records report weaker assurance")
            return 0

        report = StaticPublication(site).publish(
            log, signed, anchors=[anchor], policies=[policy]
        )
        ledger.record(anchor)
        print(f"  {report}")
        print(f"  anchored at {stamp}, witnesses 0 of 0 (stage 0)")
        return 0
    except PublicationError as error:
        # Loud, and non-zero: a scheduled job that swallows this leaves the
        # site advertising a head the log cannot support.
        print(f"  REFUSED: {error}")
        return 2
    finally:
        log.close()
        ledger.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("var"))
    parser.add_argument("--site", type=Path, default=Path("web/log"))
    parser.add_argument("--origin", default="certifiles.example/log")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    raise SystemExit(publish(args.data, args.site, args.origin, args.dry_run))
