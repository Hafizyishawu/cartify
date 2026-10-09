"""HTTP service tests, driven against a real server on a real socket.

Most of these check that a request is refused. The auth half is the first
network-facing part of this project, and the interesting cases are the ones
where someone is trying to skip a step.
"""

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.cookies import SimpleCookie
from pathlib import Path

from certifiles.accounts import AccountStore, totp_code
from certifiles.log import TransparencyLog
from certifiles.alerts import AlertStore
from certifiles.nearmatch import NearMatchIndex
from certifiles.ratelimit import DOMAIN_CHECK, SIGN_IN, WORK_REGISTRATION, RateLimiter
from certifiles.record import AssuranceLevel
from certifiles.similarity import SimilarityFingerprint, SimilarityKind
from certifiles.service import SESSION_COOKIE, Services, serve
from certifiles.sessions import SessionStore

EMAIL = "amara@example.com"
PASSWORD = "correct horse battery staple"
SHA = "a" * 64


class Client:
    """A tiny cookie-keeping HTTP client, so sessions behave like a browser."""

    def __init__(self, base):
        self.base = base
        self.cookie = None
        self.csrf = None

    def request(self, method, path, body=None, csrf=True, headers=None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(f"{self.base}{path}", data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if self.cookie:
            request.add_header("Cookie", f"{SESSION_COOKIE}={self.cookie}")
        if csrf and self.csrf:
            request.add_header("X-CSRF-Token", self.csrf)
        for key, value in (headers or {}).items():
            request.add_header(key, value)
        try:
            with urllib.request.urlopen(request) as response:
                self._store_cookie(response.headers)
                return response.status, json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as error:
            self._store_cookie(error.headers)
            raw = error.read()
            try:
                return error.code, json.loads(raw or b"{}")
            except ValueError:
                return error.code, {"raw": raw[:200].decode(errors="replace")}

    def _store_cookie(self, headers):
        for value in headers.get_all("Set-Cookie") or []:
            jar = SimpleCookie(value)
            if SESSION_COOKIE in jar:
                self.cookie = jar[SESSION_COOKIE].value or None

    def refresh_csrf(self):
        _, me = self.request("GET", "/api/me", csrf=False)
        self.csrf = me.get("csrf_token")
        return me


class ServiceTestCase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        web = Path(self.directory.name)
        (web / "index.html").write_text("<h1>verify</h1>")

        self.accounts = AccountStore()
        self.sessions = SessionStore()
        self.limiter = RateLimiter()
        self.log = TransparencyLog()
        for store in (self.accounts, self.sessions, self.limiter, self.log):
            self.addCleanup(store.close)

        self.services = Services(
            accounts=self.accounts, sessions=self.sessions, limiter=self.limiter,
            log=self.log, web_root=web, secure_cookies=False,
            resolver=self.make_resolver(), domain_secret=b"test-server-secret",
        )
        self.server = serve(self.services, port=0)
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.client = Client(f"http://127.0.0.1:{self.server.server_address[1]}")

    def make_resolver(self):
        """No resolver by default, so nothing accidentally reaches the network."""
        return None

    def signed_up(self, client=None):
        client = client or self.client
        client.request("POST", "/api/accounts", {"email": EMAIL, "password": PASSWORD})
        client.refresh_csrf()
        return client

    def with_mfa(self, client=None):
        client = self.signed_up(client)
        status, body = client.request("POST", "/api/mfa/enrol", {})
        secret_b32 = body["otpauth_uri"].split("secret=")[1].split("&")[0]
        import base64

        secret = base64.b32decode(secret_b32 + "=" * (-len(secret_b32) % 8))
        import time as _t

        code = totp_code(secret, int(_t.time() // 30))
        client.request("POST", "/api/mfa/confirm", {"code": code})
        client.refresh_csrf()
        return client, secret


class TestPublicPaths(ServiceTestCase):
    def test_the_site_is_served_without_a_session(self):
        # Verification is public. If this ever needs a cookie, the product is
        # broken in the way the threat model warns about.
        request = urllib.request.Request(f"{self.client.base}/index.html")
        with urllib.request.urlopen(request) as response:
            self.assertEqual(response.status, 200)

    def test_me_reports_signed_out_rather_than_failing(self):
        status, body = self.client.request("GET", "/api/me", csrf=False)
        self.assertEqual(status, 200)
        self.assertFalse(body["signed_in"])

    def test_security_headers_are_set(self):
        with urllib.request.urlopen(f"{self.client.base}/index.html") as response:
            self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
            self.assertEqual(response.headers["X-Frame-Options"], "DENY")

    def test_a_path_cannot_escape_the_web_root(self):
        for attempt in ("/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd",
                        "/....//....//etc/passwd"):
            with self.subTest(path=attempt):
                request = urllib.request.Request(f"{self.client.base}{attempt}")
                try:
                    with urllib.request.urlopen(request) as response:
                        self.assertNotIn(b"root:", response.read())
                except urllib.error.HTTPError as error:
                    self.assertIn(error.code, (400, 404))

    def test_an_unknown_endpoint_is_a_clean_404(self):
        status, _ = self.client.request("POST", "/api/nope", {})
        self.assertEqual(status, 404)


class TestAccountCreation(ServiceTestCase):
    def test_creating_an_account_starts_a_session_without_mfa(self):
        status, body = self.client.request(
            "POST", "/api/accounts", {"email": EMAIL, "password": PASSWORD}
        )
        self.assertEqual(status, 201)
        self.assertEqual(body["next"], "enrol-mfa")
        me = self.client.refresh_csrf()
        self.assertTrue(me["signed_in"])
        self.assertFalse(me["may_register_works"])

    def test_a_weak_password_is_refused(self):
        status, body = self.client.request(
            "POST", "/api/accounts", {"email": EMAIL, "password": "short"}
        )
        self.assertEqual(status, 400)
        self.assertIn("12 characters", body["error"])

    def test_a_duplicate_address_is_refused(self):
        self.client.request("POST", "/api/accounts", {"email": EMAIL, "password": PASSWORD})
        status, _ = self.client.request(
            "POST", "/api/accounts", {"email": EMAIL, "password": PASSWORD}
        )
        self.assertEqual(status, 400)

    def test_a_malformed_body_is_refused(self):
        request = urllib.request.Request(
            f"{self.client.base}/api/accounts", data=b"not json", method="POST"
        )
        try:
            urllib.request.urlopen(request)
            self.fail("expected a rejection")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 400)


class TestSignIn(ServiceTestCase):
    def test_the_right_credentials_sign_in(self):
        self.signed_up()
        self.client.request("POST", "/api/sign-out", {})
        status, body = self.client.request(
            "POST", "/api/sign-in", {"email": EMAIL, "password": PASSWORD}
        )
        self.assertEqual(status, 200)

    def test_wrong_password_and_unknown_address_give_the_same_answer(self):
        # Different messages would let an attacker enumerate registered users.
        self.signed_up()
        _, wrong = self.client.request(
            "POST", "/api/sign-in", {"email": EMAIL, "password": "wrong password!!"}
        )
        _, unknown = self.client.request(
            "POST", "/api/sign-in", {"email": "nobody@example.com", "password": PASSWORD}
        )
        self.assertEqual(wrong["error"], unknown["error"])

    def test_sign_in_is_rate_limited(self):
        for _ in range(SIGN_IN.allowed):
            self.client.request("POST", "/api/sign-in",
                                {"email": EMAIL, "password": "wrong password!!"})
        status, body = self.client.request(
            "POST", "/api/sign-in", {"email": EMAIL, "password": "wrong password!!"}
        )
        self.assertEqual(status, 429)

    def test_signing_out_clears_the_session(self):
        self.signed_up()
        self.client.request("POST", "/api/sign-out", {})
        _, me = self.client.request("GET", "/api/me", csrf=False)
        self.assertFalse(me["signed_in"])

    def test_an_active_factor_still_requires_the_code_after_sign_in(self):
        client, secret = self.with_mfa()
        client.request("POST", "/api/sign-out", {})
        _, body = client.request("POST", "/api/sign-in",
                                 {"email": EMAIL, "password": PASSWORD})
        self.assertEqual(body["next"], "verify-mfa")
        me = client.refresh_csrf()
        self.assertFalse(me["may_register_works"])


class TestSecondFactorFlow(ServiceTestCase):
    def test_enrolment_returns_an_otpauth_uri(self):
        self.signed_up()
        status, body = self.client.request("POST", "/api/mfa/enrol", {})
        self.assertEqual(status, 200)
        self.assertTrue(body["otpauth_uri"].startswith("otpauth://totp/"))

    def test_a_wrong_code_does_not_activate(self):
        self.signed_up()
        self.client.request("POST", "/api/mfa/enrol", {})
        status, _ = self.client.request("POST", "/api/mfa/confirm", {"code": "000000"})
        self.assertEqual(status, 401)

    def test_confirming_rotates_the_session_token(self):
        # A token captured before the second factor must not inherit the
        # authority granted after it.
        self.signed_up()
        before = self.client.cookie
        self.client.request("POST", "/api/mfa/enrol", {})
        client, _ = self.with_mfa(self.client) if False else (self.client, None)
        # enrol again is refused once active, so drive the flow directly
        import base64, time as _t

        _, body = self.client.request("POST", "/api/mfa/enrol", {})
        b32 = body["otpauth_uri"].split("secret=")[1].split("&")[0]
        secret = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        self.client.request("POST", "/api/mfa/confirm",
                            {"code": totp_code(secret, int(_t.time() // 30))})
        self.assertNotEqual(self.client.cookie, before)

    def test_enrolling_twice_is_refused_once_active(self):
        client, _ = self.with_mfa()
        status, _ = client.request("POST", "/api/mfa/enrol", {})
        self.assertEqual(status, 409)


class TestRegisteringWork(ServiceTestCase):
    def payload(self, sha=SHA):
        return {
            "sha256": sha, "media_type": "image/png", "size_bytes": 1024,
            "similarity_fingerprints": {"phash": "c3a90f7e21b45d80"},
            "derivation_version": 1, "quality": 84,
            "claim_type": "created",
        }

    def test_a_signed_in_account_with_mfa_can_register(self):
        client, _ = self.with_mfa()
        status, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 201)
        self.assertEqual(body["position"], 0)
        self.assertEqual(self.log.size(), 1)

    def test_the_log_receives_the_opaque_identity_not_the_email(self):
        # The log cannot honour an erasure request, so an address must never
        # reach it.
        client, _ = self.with_mfa()
        client.request("POST", "/api/works", self.payload())
        leaf = self.log.entry(0).leaf_data.decode()
        self.assertNotIn(EMAIL, leaf)
        self.assertNotIn("example.com", leaf)

    def test_registering_requires_a_session(self):
        status, _ = self.client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 401)
        self.assertEqual(self.log.size(), 0)

    def test_registering_requires_a_passed_second_factor(self):
        # Checked at the write, not at sign-in, so an account cannot accumulate
        # records while its factor is merely pending.
        self.signed_up()
        status, _ = self.client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 403)
        self.assertEqual(self.log.size(), 0)

    def test_registering_requires_a_csrf_token(self):
        client, _ = self.with_mfa()
        status, _ = client.request("POST", "/api/works", self.payload(), csrf=False)
        self.assertEqual(status, 403)
        self.assertEqual(self.log.size(), 0)

    def test_a_wrong_csrf_token_is_refused(self):
        client, _ = self.with_mfa()
        client.csrf = "0" * 64
        status, _ = client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 403)

    def test_an_invalid_record_never_reaches_the_log(self):
        client, _ = self.with_mfa()
        status, _ = client.request("POST", "/api/works", self.payload(sha="NOT A HASH"))
        self.assertEqual(status, 400)
        self.assertEqual(self.log.size(), 0)

    def test_registration_is_rate_limited(self):
        # The threat model's mass pre-emptive registration attack.
        client, _ = self.with_mfa()
        for n in range(WORK_REGISTRATION.allowed):
            client.request("POST", "/api/works", self.payload(sha=f"{n:064x}"))
        status, body = client.request("POST", "/api/works", self.payload(sha="f" * 64))
        self.assertEqual(status, 429)
        self.assertEqual(self.log.size(), WORK_REGISTRATION.allowed)

    def test_the_assurance_recorded_is_the_accounts_current_level(self):
        client, _ = self.with_mfa()
        _, me = client.request("GET", "/api/me", csrf=False)
        self.accounts.set_assurance(me["identity_id"], AssuranceLevel.DOMAIN)
        _, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(body["assurance_level"], "domain")

    def test_one_account_cannot_register_as_another(self):
        # The identity in a record comes from the session, never from the body.
        client, _ = self.with_mfa()
        payload = self.payload()
        payload["identity_id"] = "someone-elses-identity"
        client.request("POST", "/api/works", payload)
        leaf = self.log.entry(0).leaf_data.decode()
        self.assertNotIn("someone-elses-identity", leaf)


class TestIndexing(ServiceTestCase):
    """Registering a work makes it searchable, and never depends on doing so.

    The log entry is the record. The index is a convenience rebuildable from it,
    so the two are ordered deliberately: a work is logged first, and a failure
    to index afterwards is reported rather than rolled back.
    """

    def setUp(self):
        super().setUp()
        self.index = NearMatchIndex()
        self.addCleanup(self.index.close)
        self.services.index = self.index

    def payload(self, sha=SHA, **extra):
        body = {
            "sha256": sha, "media_type": "image/png", "size_bytes": 1024,
            "similarity_fingerprints": {"phash": "c3a90f7e21b45d80"},
            "derivation_version": 1, "claim_type": "created",
        }
        body.update(extra)
        return body

    def test_a_registered_work_becomes_searchable(self):
        client, _ = self.with_mfa()
        status, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 201)
        self.assertTrue(body["searchable"])
        self.assertEqual(self.index.size(), 1)

    def test_the_indexed_position_is_the_log_position(self):
        # An index keyed to the wrong position would surface the wrong record
        # to an artist, which is an accusation pointed at a stranger.
        client, _ = self.with_mfa()
        client.request("POST", "/api/works", self.payload(sha="a" * 64))
        _, second = client.request("POST", "/api/works", self.payload(sha="b" * 64))
        found = self.index.search(
            [SimilarityFingerprint(SimilarityKind.PHASH, "c3a90f7e21b45d80")]
        )
        self.assertEqual(sorted(c.position for c in found), [0, 1])
        self.assertEqual(second["position"], 1)

    def test_a_work_with_no_fingerprints_is_never_offered_to_the_index(self):
        # Not an error. Most files are not images, and a work that cannot be
        # searched should say so rather than occupy an empty index row.
        #
        # Asserting the call never happens, not just that nothing was stored:
        # the index refuses an empty set on its own, so a test that only
        # checked size would pass with the guard removed and rely on an
        # exception for ordinary control flow.
        calls = []

        class Recording:
            def add(self, *args, **kwargs):
                calls.append(args)

        self.services.index = Recording()
        client, _ = self.with_mfa()
        status, body = client.request(
            "POST", "/api/works", self.payload(similarity_fingerprints={},
                                               derivation_version=None))
        self.assertEqual(status, 201)
        self.assertEqual(calls, [])
        self.assertFalse(body["searchable"])

    def test_an_index_failure_does_not_lose_the_registration(self):
        class Broken:
            def add(self, *_args, **_kwargs):
                raise RuntimeError("index unavailable")

        self.services.index = Broken()
        client, _ = self.with_mfa()
        status, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 201)
        self.assertFalse(body["searchable"])
        self.assertEqual(self.log.size(), 1)

    def test_indexing_survives_an_absent_quality(self):
        # Derivation version 1 computes no quality, so this is the ordinary
        # case rather than an edge one.
        client, _ = self.with_mfa()
        client.request("POST", "/api/works", self.payload())
        found = self.index.search(
            [SimilarityFingerprint(SimilarityKind.PHASH, "c3a90f7e21b45d80")]
        )
        self.assertEqual(len(found), 1)
        self.assertIsNone(found[0].quality)
        self.assertFalse(found[0].quality_capped)

    def test_a_near_match_queues_an_alert_for_the_earlier_registrant(self):
        store = AlertStore()
        self.addCleanup(store.close)
        self.services.alerts = store

        first, _ = self.with_mfa()
        first.request("POST", "/api/works", self.payload(sha="a" * 64))

        second = Client(self.client.base)
        second.request("POST", "/api/accounts",
                       {"email": "other@example.com", "password": PASSWORD})
        second.refresh_csrf()
        _, enrol = second.request("POST", "/api/mfa/enrol", {})
        import base64
        import time as _t
        b32 = enrol["otpauth_uri"].split("secret=")[1].split("&")[0]
        secret = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        second.request("POST", "/api/mfa/confirm",
                       {"code": totp_code(secret, int(_t.time() // 30))})
        second.refresh_csrf()
        second.request("POST", "/api/works", self.payload(sha="b" * 64))

        queued = store.undelivered()
        self.assertEqual(len(queued), 1)
        self.assertEqual((queued[0].subject_position, queued[0].candidate_position), (0, 1))

    def test_registering_against_your_own_work_queues_nothing(self):
        store = AlertStore()
        self.addCleanup(store.close)
        self.services.alerts = store
        client, _ = self.with_mfa()
        client.request("POST", "/api/works", self.payload(sha="a" * 64))
        client.request("POST", "/api/works", self.payload(sha="b" * 64))
        self.assertEqual(store.undelivered(), [])

    def test_an_alert_failure_does_not_lose_the_registration(self):
        class Broken:
            def queue(self, *_a, **_k):
                raise RuntimeError("alert store unavailable")

        self.services.alerts = Broken()
        client, _ = self.with_mfa()
        status, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 201)
        self.assertEqual(self.log.size(), 1)
        # Reported, not swallowed. An alert channel that has quietly stopped
        # working looks exactly like one with nothing to say.
        self.assertIsNone(body["alerts_queued"])

    def test_a_successful_registration_reports_how_many_alerts_it_queued(self):
        store = AlertStore()
        self.addCleanup(store.close)
        self.services.alerts = store
        client, _ = self.with_mfa()
        _, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(body["alerts_queued"], 0)

    def test_nothing_is_indexed_when_no_index_is_configured(self):
        self.services.index = None
        client, _ = self.with_mfa()
        status, body = client.request("POST", "/api/works", self.payload())
        self.assertEqual(status, 201)
        self.assertFalse(body["searchable"])


class TestMonitoring(ServiceTestCase):
    """The dashboard's data, scoped by session rather than by a parameter."""

    def setUp(self):
        super().setUp()
        self.index = NearMatchIndex()
        self.addCleanup(self.index.close)
        self.services.index = self.index

    def payload(self, sha, phash):
        return {
            "sha256": sha, "media_type": "image/png", "size_bytes": 1024,
            "similarity_fingerprints": {"phash": phash},
            "derivation_version": 1, "claim_type": "created",
        }

    def other_account(self, email):
        import base64
        import time as _t

        client = Client(self.client.base)
        client.request("POST", "/api/accounts", {"email": email, "password": PASSWORD})
        client.refresh_csrf()
        _, enrol = client.request("POST", "/api/mfa/enrol", {})
        b32 = enrol["otpauth_uri"].split("secret=")[1].split("&")[0]
        secret = base64.b32decode(b32 + "=" * (-len(b32) % 8))
        client.request("POST", "/api/mfa/confirm",
                       {"code": totp_code(secret, int(_t.time() // 30))})
        client.refresh_csrf()
        return client

    def test_monitoring_needs_a_session(self):
        status, _ = self.client.request("GET", "/api/monitoring", csrf=False)
        self.assertEqual(status, 401)

    def test_it_returns_only_the_callers_own_works(self):
        # The published log is public and the old page took an identity from
        # the query string, so anyone could read anyone's monitoring view.
        mine, _ = self.with_mfa()
        mine.request("POST", "/api/works", self.payload("a" * 64, "ffffffffffffffff"))
        theirs = self.other_account("other@example.com")
        theirs.request("POST", "/api/works", self.payload("b" * 64, "0000000000000000"))

        _, body = mine.request("GET", "/api/monitoring", csrf=False)
        self.assertEqual([w["position"] for w in body["works"]], [0])

    def test_a_later_near_match_by_someone_else_is_reported(self):
        mine, _ = self.with_mfa()
        mine.request("POST", "/api/works", self.payload("a" * 64, "ffffffffffffffff"))
        theirs = self.other_account("other@example.com")
        theirs.request("POST", "/api/works", self.payload("b" * 64, "fffffffffffffffc"))

        _, body = mine.request("GET", "/api/monitoring", csrf=False)
        self.assertEqual(len(body["matches"]), 1)
        match = body["matches"][0]
        self.assertEqual((match["subject_position"], match["candidate_position"]), (0, 1))
        self.assertEqual(match["candidate"]["assurance_level"], "unverified")

    def test_your_own_later_work_is_never_reported_as_a_match(self):
        mine, _ = self.with_mfa()
        mine.request("POST", "/api/works", self.payload("a" * 64, "ffffffffffffffff"))
        mine.request("POST", "/api/works", self.payload("b" * 64, "fffffffffffffffc"))
        _, body = mine.request("GET", "/api/monitoring", csrf=False)
        self.assertEqual(body["matches"], [])

    def test_an_earlier_work_by_someone_else_is_not_reported(self):
        # Only later registrations can be copies. An earlier one cannot be.
        theirs = self.other_account("other@example.com")
        theirs.request("POST", "/api/works", self.payload("b" * 64, "fffffffffffffffc"))
        mine, _ = self.with_mfa()
        mine.request("POST", "/api/works", self.payload("a" * 64, "ffffffffffffffff"))
        _, body = mine.request("GET", "/api/monitoring", csrf=False)
        self.assertEqual(body["matches"], [])

    def test_an_account_with_no_works_gets_an_empty_view(self):
        client, _ = self.with_mfa()
        _, body = client.request("GET", "/api/monitoring", csrf=False)
        self.assertEqual((body["works"], body["matches"]), ([], []))
        self.assertTrue(body["searched"])

    def test_no_index_is_reported_rather_than_read_as_nothing_found(self):
        # An absent index means the search did not run. Rendering that as "no
        # matches" would tell an artist they are safe on the strength of a
        # search nobody performed.
        self.services.index = None
        client, _ = self.with_mfa()
        client.request("POST", "/api/works", self.payload("a" * 64, "ffffffffffffffff"))
        _, body = client.request("GET", "/api/monitoring", csrf=False)
        self.assertFalse(body["searched"])


class TestNotFound(ServiceTestCase):
    """A dead link is the common way to arrive at a 404 on this product.

    404.html exists to say that a stale record link does not mean the record is
    fake, which is the wrong thing to answer with a JSON blob.
    """

    def setUp(self):
        super().setUp()
        (self.services.web_root / "404.html").write_text("<h1>no such page</h1>")

    def test_a_missing_page_serves_the_404_page(self):
        status, body = self.client.request("GET", "/gone.html", csrf=False)
        self.assertEqual(status, 404)
        self.assertIn("no such page", body.get("raw", ""))

    def test_a_path_with_no_extension_serves_the_404_page(self):
        status, body = self.client.request("GET", "/r/12345", csrf=False)
        self.assertEqual(status, 404)
        self.assertIn("no such page", body.get("raw", ""))

    def test_a_missing_asset_still_answers_json(self):
        # Rendering a page into a fetch would misreport what actually failed.
        status, body = self.client.request("GET", "/missing.js", csrf=False)
        self.assertEqual(status, 404)
        self.assertEqual(body.get("error"), "Not found.")

    def test_the_404_page_carries_the_security_headers(self):
        request = urllib.request.Request(f"{self.client.base}/gone.html")
        try:
            urllib.request.urlopen(request)
            self.fail("expected 404")
        except urllib.error.HTTPError as error:
            self.assertEqual(error.code, 404)
            self.assertEqual(error.headers["X-Content-Type-Options"], "nosniff")
            self.assertIn("default-src", error.headers["Content-Security-Policy"])


class TestSessionHandling(ServiceTestCase):
    def test_a_forged_cookie_is_not_a_session(self):
        self.client.cookie = "a" * 43
        _, me = self.client.request("GET", "/api/me", csrf=False)
        self.assertFalse(me["signed_in"])

    def test_the_cookie_is_httponly_and_samesite(self):
        request = urllib.request.Request(
            f"{self.client.base}/api/accounts",
            data=json.dumps({"email": EMAIL, "password": PASSWORD}).encode(),
            method="POST",
        )
        request.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(request) as response:
            cookie = response.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)


if __name__ == "__main__":
    unittest.main()


class StubResolver:
    """Stands in for DNS. Returns, or raises, whatever the test asked for."""

    def __init__(self, result):
        self.result = result
        self.names = []

    def txt(self, name):
        self.names.append(name)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class TestDomainVerification(ServiceTestCase):
    """The three outcomes, and the difference between two of them.

    "Not published" and "not checked" look similar in a UI and are not the same
    claim at all. One says the resolvers answered and the record was absent; the
    other says nothing about the domain, only about our lookup.
    """

    published = []

    def make_resolver(self):
        self.resolver = StubResolver(self.published)
        return self.resolver

    def challenge(self, client, domain="example.com"):
        status, body = client.request("POST", "/api/domain/challenge", {"domain": domain})
        self.assertEqual(status, 200)
        return body

    def test_a_challenge_needs_a_session(self):
        status, _ = self.client.request("POST", "/api/domain/challenge",
                                        {"domain": "example.com"}, csrf=False)
        self.assertEqual(status, 401)

    def test_a_check_needs_a_session(self):
        status, _ = self.client.request("POST", "/api/domain/verify",
                                        {"domain": "example.com"}, csrf=False)
        self.assertEqual(status, 401)

    def test_a_check_needs_a_csrf_token(self):
        client, _ = self.with_mfa()
        status, _ = client.request("POST", "/api/domain/verify",
                                   {"domain": "example.com"}, csrf=False)
        self.assertEqual(status, 403)

    def test_the_challenge_names_the_record_to_publish(self):
        client, _ = self.with_mfa()
        body = self.challenge(client)
        self.assertEqual(body["record_name"], "_certifiles.example.com")
        self.assertTrue(body["record_value"].startswith("certifiles-domain-verification="))

    def test_two_accounts_get_different_challenges_for_one_domain(self):
        # Otherwise anyone could watch for a real owner to publish and claim the
        # domain the instant the record appears.
        from certifiles.domains import challenge_for

        client, _ = self.with_mfa()
        mine = self.challenge(client)["record_value"]
        other = self.accounts.create("other@example.com", PASSWORD)
        theirs = challenge_for(other.identity_id, "example.com", b"test-server-secret")
        self.assertNotEqual(mine, theirs.record_value)

    def confirmed(self):
        """A signed-in account that has confirmed its email address."""
        client, _ = self.with_mfa()
        _, me = client.request("GET", "/api/me", csrf=False)
        self.accounts.mark_email_verified(me["identity_id"])
        return client

    def test_a_published_record_proves_the_domain(self):
        client = self.confirmed()
        self.resolver.result = [self.challenge(client)["record_value"]]
        status, body = client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(status, 200)
        self.assertEqual(body["assurance_level"], "domain")
        _, me = client.request("GET", "/api/me", csrf=False)
        self.assertEqual(me["assurance_level"], "domain")

    def test_the_lookup_asks_for_the_challenge_name(self):
        client = self.confirmed()
        self.resolver.result = [self.challenge(client)["record_value"]]
        client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(self.resolver.names, ["_certifiles.example.com"])

    def test_an_unconfirmed_address_cannot_prove_a_domain(self):
        # The ladder is climbed in order. A domain proof is the stronger claim
        # but does not make the account reachable, and skipping the rung would
        # leave the level asserting an email check that never happened.
        client, _ = self.with_mfa()
        self.resolver.result = [self.challenge(client)["record_value"]]
        status, _ = client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(status, 403)
        _, me = client.request("GET", "/api/me", csrf=False)
        self.assertEqual(me["assurance_level"], "unverified")

    def test_a_refused_ladder_skip_spends_no_lookup(self):
        # Refusing on policy is not the caller misbehaving, so it costs them
        # nothing and costs us no outbound request.
        client, _ = self.with_mfa()
        self.resolver.result = [self.challenge(client)["record_value"]]
        client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(self.resolver.names, [])

    def test_the_record_can_be_prepared_before_the_address_is_confirmed(self):
        # Publishing DNS is the slow half. An unconfirmed account can still take
        # the record away and publish it while the email is in flight.
        client, _ = self.with_mfa()
        body = self.challenge(client)
        self.assertTrue(body["record_value"].startswith("certifiles-domain-verification="))

    def test_the_challenge_survives_confirming_the_address(self):
        # It is derived from the identity and the domain, not from the level, so
        # a record published early still matches after the rung is cleared.
        client, _ = self.with_mfa()
        before = self.challenge(client)["record_value"]
        _, me = client.request("GET", "/api/me", csrf=False)
        self.accounts.mark_email_verified(me["identity_id"])
        self.assertEqual(self.challenge(client)["record_value"], before)

    def test_an_absent_record_is_a_client_error_and_changes_nothing(self):
        client = self.confirmed()
        self.challenge(client)
        self.resolver.result = []
        status, _ = client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(status, 400)
        _, me = client.request("GET", "/api/me", csrf=False)
        self.assertEqual(me["assurance_level"], "email")

    def test_another_accounts_record_does_not_prove_the_domain(self):
        client = self.confirmed()
        other = self.accounts.create("other@example.com", PASSWORD)
        from certifiles.domains import challenge_for

        theirs = challenge_for(other.identity_id, "example.com", b"test-server-secret")
        self.resolver.result = [theirs.record_value]
        status, _ = client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(status, 400)

    def test_a_failed_lookup_is_503_not_a_failed_proof(self):
        # The distinction the design turns on. A DNS outage must never read as
        # "you do not control this domain".
        client = self.confirmed()
        self.challenge(client)
        self.resolver.result = RuntimeError("resolvers disagreed")
        status, _ = client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(status, 503)
        _, me = client.request("GET", "/api/me", csrf=False)
        self.assertEqual(me["assurance_level"], "email")

    def test_a_malformed_domain_is_400_not_503(self):
        # Reporting a typo as a service outage sends the user to wait for a
        # recovery that will never come.
        client = self.confirmed()
        status, _ = client.request("POST", "/api/domain/verify", {"domain": "not a domain"})
        self.assertEqual(status, 400)

    def test_a_malformed_domain_is_never_looked_up(self):
        client = self.confirmed()
        client.request("POST", "/api/domain/verify", {"domain": "not a domain"})
        self.assertEqual(self.resolver.names, [])

    def test_checks_are_rate_limited_before_any_lookup_happens(self):
        # This endpoint spends outbound requests to resolvers we do not run, so
        # the limit has to bite before the request goes out, not after.
        client = self.confirmed()
        self.challenge(client)
        self.resolver.result = []
        for _ in range(DOMAIN_CHECK.allowed):
            client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        status, _ = client.request("POST", "/api/domain/verify", {"domain": "example.com"})
        self.assertEqual(status, 429)
        self.assertEqual(len(self.resolver.names), DOMAIN_CHECK.allowed)
