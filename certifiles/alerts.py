"""Telling an artist that something resembling their work was registered.

This is the subscription, and it is also the most dangerous message this product
sends. An alert reaches a person who is already worried about being copied, and
it names a stranger. Every rule here exists because getting that wrong turns a
search result into an accusation the recipient then acts on.

**Queued, not sent inline.** Registration writes rows; delivery reads them.
Putting an SMTP round trip inside the write path would make registering a work
as slow and as failure-prone as the mail server, and a claim that is already in
the log must not be held hostage to a notification about it.

**Nothing is said twice.** One alert per recipient per pair, ever. A person told
the same thing twice learns to ignore the channel, and this channel is the
product.

**The channel is attacker controlled.** Anyone can cause alerts to a chosen
artist by registering near-matches to their work, so the daily cap in
AlertPolicy is a safety control rather than a courtesy. It is applied at
delivery, where the count is known, not at planning time.

**Delivery failure is not loss.** A row stays pending until it is sent or has
been tried enough times to conclude the address is not reachable, at which point
it is abandoned rather than retried forever against a mailbox that no longer
exists.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence

from certifiles.mail import Message
from certifiles.nearmatch import AlertPolicy, monitor

# Beyond this a bounced or rejected address is not going to start working, and
# the rows are just a queue that never drains.
MAX_ATTEMPTS = 5

DAY_SECONDS = 24 * 3600


class AlertError(RuntimeError):
    """The alert store refused an operation."""


@dataclass(frozen=True, slots=True)
class PendingAlert:
    recipient_identity: str
    #: The recipient's own earlier work.
    subject_position: int
    #: The later registration that resembles it.
    candidate_position: int
    band: str
    distances: Mapping[str, int]


SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    recipient_identity TEXT NOT NULL,
    subject_position   INTEGER NOT NULL,
    candidate_position INTEGER NOT NULL,
    band               TEXT NOT NULL,
    distances          TEXT NOT NULL,
    queued_at          INTEGER NOT NULL,
    sent_at            INTEGER,
    attempts           INTEGER NOT NULL DEFAULT 0,
    -- One row per pair per recipient, enforced here rather than by a check the
    -- caller has to remember, so a replayed registration cannot double up.
    PRIMARY KEY (recipient_identity, subject_position, candidate_position)
);

CREATE INDEX IF NOT EXISTS alerts_undelivered
    ON alerts (sent_at, attempts) WHERE sent_at IS NULL;
CREATE INDEX IF NOT EXISTS alerts_by_recipient ON alerts (recipient_identity, sent_at);
"""


class AlertStore:
    def __init__(self, path: str | Path = ":memory:") -> None:
        self._connection = sqlite3.connect(
            str(path), isolation_level=None, check_same_thread=False
        )
        self._connection.execute("PRAGMA journal_mode=WAL")
        self._connection.executescript(SCHEMA)

    def close(self) -> None:
        self._connection.close()

    def __enter__(self) -> "AlertStore":
        return self

    def __exit__(self, *_exc) -> None:
        self.close()

    def queue(self, alerts: Sequence[PendingAlert], now: int | None = None) -> int:
        """Add alerts, silently skipping any pair already known.

        INSERT OR IGNORE rather than a read followed by a write: two
        registrations racing on the same pair would otherwise both see nothing
        and both insert.
        """
        now = int(time.time()) if now is None else now
        before = self._connection.total_changes
        self._connection.executemany(
            "INSERT OR IGNORE INTO alerts (recipient_identity, subject_position,"
            " candidate_position, band, distances, queued_at)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            [
                (a.recipient_identity, a.subject_position, a.candidate_position,
                 a.band, json.dumps(a.distances, sort_keys=True), now)
                for a in alerts
            ],
        )
        return self._connection.total_changes - before

    def undelivered(self, limit: int = 100) -> list[PendingAlert]:
        rows = self._connection.execute(
            "SELECT recipient_identity, subject_position, candidate_position, band,"
            " distances FROM alerts WHERE sent_at IS NULL AND attempts < ?"
            " ORDER BY queued_at, subject_position LIMIT ?",
            (MAX_ATTEMPTS, limit),
        ).fetchall()
        return [
            PendingAlert(row[0], row[1], row[2], row[3], json.loads(row[4]))
            for row in rows
        ]

    def sent_in_last_day(self, recipient_identity: str, now: int | None = None) -> int:
        now = int(time.time()) if now is None else now
        return self._connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE recipient_identity = ?"
            " AND sent_at IS NOT NULL AND sent_at > ?",
            (recipient_identity, now - DAY_SECONDS),
        ).fetchone()[0]

    def mark_sent(self, alerts: Sequence[PendingAlert], now: int | None = None) -> None:
        now = int(time.time()) if now is None else now
        self._connection.executemany(
            "UPDATE alerts SET sent_at = ? WHERE recipient_identity = ?"
            " AND subject_position = ? AND candidate_position = ?",
            [(now, a.recipient_identity, a.subject_position, a.candidate_position)
             for a in alerts],
        )

    def mark_attempted(self, alerts: Sequence[PendingAlert]) -> None:
        """Count a failed delivery, so a dead address eventually stops costing."""
        self._connection.executemany(
            "UPDATE alerts SET attempts = attempts + 1 WHERE recipient_identity = ?"
            " AND subject_position = ? AND candidate_position = ?",
            [(a.recipient_identity, a.subject_position, a.candidate_position)
             for a in alerts],
        )

    def abandoned(self) -> int:
        """Alerts that exhausted their attempts, for an operator to notice."""
        return self._connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE sent_at IS NULL AND attempts >= ?",
            (MAX_ATTEMPTS,),
        ).fetchone()[0]


def plan(
    log,
    index,
    position: int,
    fingerprints: Sequence,
    quality: int | None,
    registrant_identity: str,
    policy: AlertPolicy | None = None,
) -> list[PendingAlert]:
    """Who should hear about a new registration, and about what.

    Only earlier registrants, because a later registration cannot be the thing
    that was copied from. Never the registrant themselves: uploading two
    versions of your own work is the most ordinary thing an artist does, and a
    product that emails you about yourself is broken on first use.
    """
    policy = policy or AlertPolicy()
    if not fingerprints:
        return []

    order = {"strong_candidate": 0, "possible": 1, "weak": 2}
    floor = order[str(policy.minimum_band)]

    planned = []
    for candidate in monitor(index, fingerprints, quality, position):
        if order[str(candidate.band)] > floor:
            continue
        earlier = log.entry(candidate.position)
        if earlier is None or earlier.identity_id == registrant_identity:
            continue
        planned.append(PendingAlert(
            recipient_identity=earlier.identity_id,
            subject_position=earlier.position,
            candidate_position=position,
            band=str(candidate.band),
            distances={str(k): v for k, v in candidate.distances.items()},
        ))
    return planned


def alert_message(to: str, base_url: str, alerts: Sequence[PendingAlert]) -> Message:
    """One digest per recipient, worded as a search result and nothing more.

    The wording is the product here. This message reaches someone who is already
    worried about being copied, and it names another person's registration. It
    has to be useful without licensing a conclusion the data does not support.
    """
    count = len(alerts)
    lines = [
        f"{count} registration{'' if count == 1 else 's'} resembling your work "
        f"{'was' if count == 1 else 'were'} added to the log.",
        "",
        "This is a search result, not a finding. Images resemble each other by "
        "coincidence, and the measure can be evaded deliberately, so nothing "
        "here establishes that anyone copied anything. Look at both works "
        "before you act on it.",
        "",
    ]
    for alert in sorted(alerts, key=lambda a: (a.subject_position, a.candidate_position)):
        strength = ("Independent algorithms agree on this one"
                    if alert.band == "strong_candidate"
                    else "Close on some measures and not others")
        spread = ", ".join(f"{kind} {value}" for kind, value in sorted(alert.distances.items()))
        lines += [
            f"  Your record {alert.subject_position}, "
            f"against record {alert.candidate_position}",
            f"    {strength}. Bit differences: {spread}.",
            f"    {base_url}/record.html?p={alert.candidate_position}",
            "",
        ]
    lines += [
        f"Your monitoring page: {base_url}/studio.html",
        "",
        "Certifiles records claims and the order they were made in. It does not "
        "decide who created anything, and this message is not a judgement about "
        "the other registrant.",
    ]
    return Message(
        to=to,
        subject=f"{count} registration{'' if count == 1 else 's'} resembling your work",
        body="\n".join(lines),
    )


def deliver(
    store: AlertStore,
    accounts,
    mailer,
    base_url: str,
    policy: AlertPolicy | None = None,
    now: int | None = None,
    limit: int = 100,
) -> int:
    """Send what is queued, digested per recipient. Returns messages sent.

    The daily cap is applied here rather than when planning, because the count
    that matters is what a person actually received, not what was computed for
    them. Alerts held back by the cap stay queued and go out tomorrow rather
    than being dropped.
    """
    policy = policy or AlertPolicy()
    now = int(time.time()) if now is None else now

    by_recipient: dict[str, list[PendingAlert]] = {}
    for alert in store.undelivered(limit):
        by_recipient.setdefault(alert.recipient_identity, []).append(alert)

    sent = 0
    for identity, alerts in by_recipient.items():
        already = store.sent_in_last_day(identity, now)
        room = policy.max_alerts_per_recipient_per_day - already
        if room <= 0:
            continue
        batch = alerts[:room]

        account = accounts.by_identity(identity)
        if account is None or not account.email:
            # No address to reach them at. Counted as an attempt so a deleted
            # account does not leave rows in the queue forever.
            store.mark_attempted(batch)
            continue
        try:
            mailer.send(alert_message(account.email, base_url, batch))
        except Exception:
            store.mark_attempted(batch)
            continue
        store.mark_sent(batch, now)
        sent += 1
    return sent
