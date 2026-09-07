"""TXT lookups over DNS-over-HTTPS, and the rule that two resolvers must agree.

Python's standard library cannot look up a TXT record at all: `socket` resolves
addresses, not arbitrary record types. DNS-over-HTTPS needs nothing beyond
`urllib`, and unlike plain DNS the answer arrives over an authenticated channel,
so a network position alone is not enough to forge one.

**One resolver is a single point of trust, which is the thing this product is
built to avoid.** A service whose whole claim is that you need not trust the
operator should not decide who owns a domain on one company's say-so. So a
lookup asks several independent resolvers and returns only what all of them
returned. An attacker now has to influence every one of them rather than any
one.

Failing closed matters as much as agreeing. If a resolver cannot be reached, or
two of them disagree, the answer is "this was not established", never "the
domain is not controlled". The first is a fact about the lookup; the second is a
claim about a person.
"""

from __future__ import annotations

import json
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Callable, Sequence

from certifiles.domains import TxtResolver

# Two operators, two jurisdictions, two codebases. Agreement across them is
# worth more than either alone, and the point is that they are not us.
DEFAULT_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/resolve",
)

TXT_RECORD_TYPE = 16
DEFAULT_TIMEOUT = 5
# A TXT answer that runs to kilobytes is not a verification challenge, and
# reading it would only give an unhelpful resolver a way to spend our memory.
MAX_RESPONSE_BYTES = 64 * 1024


class ResolverError(RuntimeError):
    """A lookup did not complete. Never means the record is absent."""


def _https_fetch(url: str, timeout: int) -> bytes:
    request = urllib.request.Request(url, headers={
        "Accept": "application/dns-json",
        "User-Agent": "certifiles-domain-verification",
    })
    context = ssl.create_default_context()
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        if response.status != 200:
            raise ResolverError(f"resolver answered {response.status}")
        return response.read(MAX_RESPONSE_BYTES + 1)


def _unquote(value: str) -> str:
    """Join a chunked TXT answer and strip the quoting DoH JSON adds.

    A long TXT record arrives as several quoted strings, which the DNS
    specification says to concatenate with nothing between them.
    """
    parts = [
        part[1:-1] if len(part) >= 2 and part.startswith('"') and part.endswith('"')
        else part
        for part in value.split('" "')
    ]
    joined = "".join(parts)
    if len(joined) >= 2 and joined.startswith('"') and joined.endswith('"'):
        joined = joined[1:-1]
    return joined.replace('\\"', '"')


@dataclass(frozen=True, slots=True)
class DohResolver:
    """One DNS-over-HTTPS endpoint."""

    endpoint: str
    timeout: int = DEFAULT_TIMEOUT
    fetch: Callable[[str, int], bytes] = _https_fetch

    def txt(self, name: str) -> Sequence[str]:
        if not isinstance(name, str) or not name:
            raise ResolverError("a name is required")
        query = urllib.parse.urlencode({"name": name, "type": "TXT"})
        try:
            raw = self.fetch(f"{self.endpoint}?{query}", self.timeout)
        except ResolverError:
            raise
        except Exception as error:
            raise ResolverError(f"{self.endpoint}: {error}") from error

        if len(raw) > MAX_RESPONSE_BYTES:
            raise ResolverError(f"{self.endpoint}: answer was implausibly large")
        try:
            payload = json.loads(raw)
        except ValueError as error:
            raise ResolverError(f"{self.endpoint}: answer was not JSON") from error
        if not isinstance(payload, dict):
            raise ResolverError(f"{self.endpoint}: answer was not an object")

        # Status 3 is NXDOMAIN, which is a real answer meaning the name does not
        # exist. Anything else non-zero is a failure to look up, not a finding.
        status = payload.get("Status")
        if status not in (0, 3):
            raise ResolverError(f"{self.endpoint}: lookup failed with status {status}")

        return [
            _unquote(str(answer.get("data", "")))
            for answer in payload.get("Answer", []) or []
            if isinstance(answer, dict) and answer.get("type") == TXT_RECORD_TYPE
        ]


@dataclass
class AgreeingResolver:
    """Returns only what every configured resolver returned.

    All of them must answer. Falling back to whichever one replied would hand
    an attacker a simple recipe: interfere with the honest resolver, then
    answer from the one they control.
    """

    resolvers: Sequence[TxtResolver]
    require: int | None = None

    def __post_init__(self) -> None:
        if not self.resolvers:
            raise ResolverError("at least one resolver is required")
        if self.require is None:
            self.require = len(self.resolvers)
        if not 1 <= self.require <= len(self.resolvers):
            raise ResolverError("require must be between 1 and the resolver count")

    def txt(self, name: str) -> Sequence[str]:
        answers: list[set[str]] = []
        failures: list[str] = []
        for resolver in self.resolvers:
            try:
                answers.append({str(record).strip() for record in resolver.txt(name)})
            except Exception as error:
                failures.append(str(error))

        if len(answers) < self.require:
            raise ResolverError(
                f"only {len(answers)} of {len(self.resolvers)} resolvers answered, "
                f"{self.require} required: {'; '.join(failures)}"
            )

        agreed = set.intersection(*answers) if answers else set()
        return sorted(agreed)


def default_resolver(timeout: int = DEFAULT_TIMEOUT) -> AgreeingResolver:
    return AgreeingResolver(
        [DohResolver(endpoint, timeout) for endpoint in DEFAULT_ENDPOINTS]
    )
