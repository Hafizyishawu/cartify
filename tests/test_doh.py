"""Resolver tests, with no network anywhere in them.

The fetch is injected, so every case below is about the rules rather than about
whether Cloudflare was reachable. Two of them carry the whole security argument:
a resolver that fails must never be silently dropped, and a value only one
resolver returned must never be treated as published.
"""

import json
import unittest

from certifiles.doh import (
    MAX_RESPONSE_BYTES,
    AgreeingResolver,
    DohResolver,
    ResolverError,
    default_resolver,
)
from certifiles.domains import DomainError, challenge_for, verify

NAME = "_certifiles.example.com"


def answer(*values, status=0):
    """A DoH JSON answer carrying the given TXT strings."""
    return json.dumps({
        "Status": status,
        "Answer": [{"name": NAME, "type": 16, "TTL": 300, "data": v} for v in values],
    }).encode("utf-8")


def fetcher(payload):
    def fetch(url, timeout):
        if isinstance(payload, Exception):
            raise payload
        return payload
    return fetch


class Fixed:
    """A resolver that returns, or raises, whatever it was given."""

    def __init__(self, result):
        self.result = result
        self.calls = 0

    def txt(self, name):
        self.calls += 1
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class DohParsingTests(unittest.TestCase):
    def resolve(self, payload):
        return DohResolver("https://example.invalid/dns-query", fetch=fetcher(payload)).txt(NAME)

    def test_strips_the_quoting_doh_adds(self):
        self.assertEqual(self.resolve(answer('"hello"')), ["hello"])

    def test_joins_a_chunked_record(self):
        # A TXT string over 255 bytes arrives as several quoted chunks, which
        # the DNS specification says to concatenate with nothing between them.
        self.assertEqual(self.resolve(answer('"abc" "def"')), ["abcdef"])

    def test_returns_every_txt_record_at_the_name(self):
        self.assertEqual(self.resolve(answer('"a"', '"b"')), ["a", "b"])

    def test_ignores_answers_that_are_not_txt(self):
        payload = json.dumps({
            "Status": 0,
            "Answer": [
                {"type": 5, "data": "alias.example.com."},
                {"type": 16, "data": '"real"'},
            ],
        }).encode("utf-8")
        self.assertEqual(self.resolve(payload), ["real"])

    def test_nxdomain_is_an_answer_not_a_failure(self):
        # The name does not exist, which is a fact about DNS, not a broken
        # lookup. It has to read as "no record", so the user is told to publish.
        self.assertEqual(self.resolve(json.dumps({"Status": 3}).encode("utf-8")), [])

    def test_missing_answer_key_is_empty(self):
        self.assertEqual(self.resolve(json.dumps({"Status": 0}).encode("utf-8")), [])

    def test_servfail_is_a_failure(self):
        with self.assertRaises(ResolverError):
            self.resolve(json.dumps({"Status": 2}).encode("utf-8"))

    def test_missing_status_is_a_failure(self):
        with self.assertRaises(ResolverError):
            self.resolve(json.dumps({"Answer": []}).encode("utf-8"))

    def test_non_json_is_a_failure(self):
        with self.assertRaises(ResolverError):
            self.resolve(b"<html>captive portal</html>")

    def test_json_that_is_not_an_object_is_a_failure(self):
        with self.assertRaises(ResolverError):
            self.resolve(b"[]")

    def test_an_oversized_answer_is_refused(self):
        # Valid JSON deliberately, so the size ceiling is the only thing that
        # can reject it. Parsing megabytes from an unhelpful resolver is work
        # we do not have to do.
        oversized = answer('"%s"' % ("x" * (MAX_RESPONSE_BYTES + 1)))
        self.assertGreater(len(oversized), MAX_RESPONSE_BYTES)
        with self.assertRaises(ResolverError):
            self.resolve(oversized)

    def test_a_transport_failure_becomes_a_resolver_error(self):
        with self.assertRaises(ResolverError):
            self.resolve(TimeoutError("timed out"))

    def test_an_empty_name_is_refused_without_a_lookup(self):
        called = []
        resolver = DohResolver("https://example.invalid", fetch=lambda u, t: called.append(u))
        with self.assertRaises(ResolverError):
            resolver.txt("")
        self.assertEqual(called, [])

    def test_the_name_is_url_encoded_into_the_query(self):
        seen = {}

        def fetch(url, timeout):
            seen["url"] = url
            return answer('"x"')

        DohResolver("https://example.invalid/q", fetch=fetch).txt("_a.b.example.com")
        self.assertIn("name=_a.b.example.com", seen["url"])
        self.assertIn("type=TXT", seen["url"])


class AgreementTests(unittest.TestCase):
    def test_agreement_returns_what_both_saw(self):
        resolver = AgreeingResolver([Fixed(["shared", "only-a"]), Fixed(["shared"])])
        self.assertEqual(resolver.txt(NAME), ["shared"])

    def test_a_value_only_one_resolver_saw_is_not_returned(self):
        # The security property. One resolver answering alone is exactly what a
        # cache-poisoning or split-view attack produces, and it is also what
        # ordinary mid-propagation DNS produces. Neither is proof of control.
        resolver = AgreeingResolver([Fixed(["only-a"]), Fixed([])])
        self.assertEqual(resolver.txt(NAME), [])

    def test_a_single_resolver_failing_fails_the_lookup(self):
        # Falling back to the resolver that did answer would hand an attacker a
        # recipe: disrupt the honest one, then answer from the one you control.
        resolver = AgreeingResolver([Fixed(["value"]), Fixed(ResolverError("down"))])
        with self.assertRaises(ResolverError):
            resolver.txt(NAME)

    def test_the_failure_names_which_resolvers_answered(self):
        resolver = AgreeingResolver([Fixed([]), Fixed(ResolverError("upstream refused"))])
        with self.assertRaises(ResolverError) as caught:
            resolver.txt(NAME)
        self.assertIn("1 of 2", str(caught.exception))
        self.assertIn("upstream refused", str(caught.exception))

    def test_every_resolver_is_queried_even_after_one_fails(self):
        # Short-circuiting on the first failure would make the result depend on
        # the order they happen to be configured in.
        second = Fixed(["value"])
        resolver = AgreeingResolver([Fixed(ResolverError("down")), second])
        with self.assertRaises(ResolverError):
            resolver.txt(NAME)
        self.assertEqual(second.calls, 1)

    def test_whitespace_around_a_record_does_not_break_agreement(self):
        resolver = AgreeingResolver([Fixed([" value "]), Fixed(["value"])])
        self.assertEqual(resolver.txt(NAME), ["value"])

    def test_a_lower_requirement_can_be_set_explicitly(self):
        resolver = AgreeingResolver([Fixed(["v"]), Fixed(ResolverError("down"))], require=1)
        self.assertEqual(resolver.txt(NAME), ["v"])

    def test_requiring_more_than_exist_is_refused(self):
        with self.assertRaises(ResolverError):
            AgreeingResolver([Fixed([])], require=2)

    def test_no_resolvers_is_refused(self):
        with self.assertRaises(ResolverError):
            AgreeingResolver([])

    def test_the_default_uses_more_than_one_operator(self):
        resolver = default_resolver()
        self.assertGreater(len(resolver.resolvers), 1)
        self.assertEqual(resolver.require, len(resolver.resolvers))
        endpoints = {r.endpoint for r in resolver.resolvers}
        self.assertEqual(len(endpoints), len(resolver.resolvers))


class VerificationThroughAgreementTests(unittest.TestCase):
    """The end the user actually sees: proved, not proved, or not checked."""

    def setUp(self):
        self.challenge = challenge_for("identity-1", "example.com", b"server-secret")

    def agreeing(self, *results):
        return AgreeingResolver([Fixed(r) for r in results])

    def test_both_resolvers_see_the_record(self):
        value = self.challenge.record_value
        self.assertTrue(verify(self.challenge, self.agreeing([value], [value])))

    def test_one_resolver_seeing_it_is_not_proof(self):
        value = self.challenge.record_value
        self.assertFalse(verify(self.challenge, self.agreeing([value], [])))

    def test_a_failed_lookup_is_not_a_failed_proof(self):
        # The distinction the whole design turns on. This must raise, so the
        # service answers "not checked" rather than "you do not own this".
        with self.assertRaises(DomainError):
            verify(self.challenge, self.agreeing([self.challenge.record_value],
                                                 ResolverError("down")))

    def test_an_unrelated_record_at_the_name_is_not_proof(self):
        self.assertFalse(verify(self.challenge, self.agreeing(["v=spf1 -all"],
                                                              ["v=spf1 -all"])))

    def test_a_record_merely_containing_the_value_is_not_proof(self):
        padded = f"{self.challenge.record_value} and-something-else"
        self.assertFalse(verify(self.challenge, self.agreeing([padded], [padded])))


if __name__ == "__main__":
    unittest.main()
