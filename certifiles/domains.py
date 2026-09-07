"""Proving control of a domain, which is what raises assurance above email.

An email address proves someone reads an inbox. A domain proves they control
the name a buyer or a gallery already associates with them, which is why it is
the level worth showing on a record.

The check is a DNS TXT record, and the network call sits behind a protocol so
the rules are testable without one. Two properties matter more than the
mechanism:

**The challenge is per account and unguessable.** Deriving it from the domain
would let anyone compute the value for a domain they do not own and wait for
its real owner to publish it.

**Verification is repeated, not remembered.** Domains change hands. A record
keeps the assurance it was issued under, permanently, but an account should not
keep claiming a domain it no longer controls, so the proof is rechecked and can
be withdrawn.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from typing import Protocol, Sequence

DOMAIN_PATTERN = re.compile(
    r"\A(?=.{1,253}\Z)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\Z"
)
CHALLENGE_PREFIX = "certifiles-domain-verification="
CHALLENGE_HOST = "_certifiles"


class DomainError(ValueError):
    """The domain or its proof was refused."""


@dataclass(frozen=True, slots=True)
class Challenge:
    domain: str
    record_name: str
    record_value: str

    @property
    def instructions(self) -> str:
        return (
            f"Add a TXT record at {self.record_name} with the value "
            f"{self.record_value}, then check again."
        )


class TxtResolver(Protocol):
    """Returns the TXT strings published at a name, or an empty sequence."""

    def txt(self, name: str) -> Sequence[str]: ...


def normalise_domain(domain: str) -> str:
    if not isinstance(domain, str):
        raise DomainError("domain must be a string")
    cleaned = domain.strip().lower().rstrip(".")
    if cleaned.startswith(("http://", "https://")):
        cleaned = cleaned.split("//", 1)[1].split("/", 1)[0]
    if cleaned.startswith("www."):
        cleaned = cleaned[4:]
    if not DOMAIN_PATTERN.match(cleaned):
        raise DomainError("that does not look like a domain name")
    return cleaned


def challenge_for(identity_id: str, domain: str, secret: bytes) -> Challenge:
    """A stable, unguessable challenge for this account and domain.

    Stable so the user can add the record once and check whenever they like.
    Unguessable because it is an HMAC under a server-side secret, so nobody can
    compute the value another account would need.
    """
    domain = normalise_domain(domain)
    digest = hmac.new(
        secret, f"{identity_id}\n{domain}".encode("utf-8"), hashlib.sha256
    ).hexdigest()[:32]
    return Challenge(
        domain=domain,
        record_name=f"{CHALLENGE_HOST}.{domain}",
        record_value=f"{CHALLENGE_PREFIX}{digest}",
    )


def verify(challenge: Challenge, resolver: TxtResolver) -> bool:
    """Whether the expected TXT record is published.

    Compared in constant time and matched exactly. A substring match would
    accept a record that merely contains the value, which anyone could publish
    alongside their own content.
    """
    try:
        records = resolver.txt(challenge.record_name)
    except Exception:
        # A resolver failure is not a failed proof. The caller reports that it
        # could not check, rather than that the domain is not controlled.
        raise DomainError("the DNS lookup did not complete")
    return any(
        hmac.compare_digest(str(record).strip(), challenge.record_value)
        for record in records
    )


def new_server_secret() -> bytes:
    return secrets.token_bytes(32)
