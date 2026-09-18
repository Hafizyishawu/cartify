# Test plan

Every test this product needs, what exists, and what does not.

This file exists because inline testing during development covers correctness of intent
at the moment code is written, and nothing else. It does not cover the suites that only
make sense across the whole system, the ones that need infrastructure we do not have, or
the ones nobody thinks to write because the code they would break is already green.

**Writing code still means writing its tests in the same change.** This file is the
backlog of everything that sits outside that loop, plus an honest inventory of what the
existing 467 tests actually cover.

Status markers: `done`, `partial` (exists but with a named gap), `todo`.

## Running what exists

```bash
python3 -m unittest discover -s tests
```

```bash
node web/test/cross-check.mjs
```

```bash
ruff check .
```

CI runs all three on every push. See section 8.

## Current state

| | Count | Notes |
|---|---|---|
| Python test methods | 471 | 13 files, all passing |
| JS cross-checks | 591 | 167 inclusion/checkpoint, 424 banding |
| Python modules | 19 | 4,700 lines |
| JS modules | 21 | 2 covered, 19 not |
| Web pages | 16 | 0 covered by any automated test |
| Scripts | 3 | 0 covered |
| CI pipelines | 1 | lint, tests on 3.11 and 3.13, JS cross-check |

Six modules have no dedicated test file but are exercised indirectly: `domains` and
`tokens` and `mail` through `test_recovery.py`, `sessions` and `ratelimit` through
`test_accounts.py` and `test_service.py`, `fingerprint` through `test_nearmatch.py`.
Indirect coverage tests the caller's use of a module, not the module's own contract, so
each still carries gaps listed below.

---

## 1. Unit and module

### merkle.py: `partial`

| Test | Type | Status |
|---|---|---|
| Inclusion and consistency proofs across sizes | unit | done |
| Domain separation between leaf and node hashing | unit | done |
| `MAX_TREE_SIZE` bound, no recursion on huge sizes | unit | done |
| Empty tree and single-leaf edge cases | unit | done |
| **RFC 6962 published test vectors** | conformance | todo |
| Property test: any proof verifies against the root it came from, for random trees to 10k | property | todo |
| Property test: a proof with any single bit flipped never verifies | property | todo |

RFC 6962 vectors matter more than the count suggests. Everything currently agrees with
our own implementation, which proves internal consistency and not correctness against the
standard other verifiers implement.

### record.py: `partial`

| Test | Type | Status |
|---|---|---|
| Canonicalisation determinism, sorted keys, float rejection | unit | done |
| Field sensitivity: any changed field changes the leaf hash | unit | done |
| `OPAQUE_ID_PATTERN` and `SHA256_PATTERN` validation | unit | done |
| Unicode normalisation: NFC vs NFD in titles produce distinct leaves, deliberately | unit | todo |
| Deeply nested or very large records rejected before hashing | unit | todo |
| Property test: canonicalize is stable across dict insertion orders | property | todo |
| Forward compatibility: an unknown field in a stored record fails closed, not silently | unit | todo |

### checkpoint.py: `partial`

| Test | Type | Status |
|---|---|---|
| Note format round trip, strict parsing, malformed rejection | unit | done |
| `WitnessPolicy` construction refusals (log key in witness set, duplicate keys) | unit | done |
| Quorum requires log signature plus K distinct witnesses | unit | done |
| `policy_in_force` selection by tree size | unit | done |
| **C2SP note format conformance against the published spec** | conformance | todo |
| Signature malleability: a re-encoded signature over the same body is rejected | security | todo |
| Policy version unknown to the verifier fails closed as UNVERIFIED | unit | partial |

### log.py: `partial`

| Test | Type | Status |
|---|---|---|
| Append-only triggers block UPDATE and DELETE | unit | done |
| `check_integrity()` catches count/position divergence | unit | done |
| Concurrent append under 6 threads, lock required | concurrency | done |
| Duplicate content claims | unit | done |
| Concurrent append at 64 threads sustained, no lost writes | concurrency | todo |
| WAL recovery after process kill mid-append | operational | todo |
| Behaviour when the database file is read-only or the disk is full | operational | todo |

### anchoring.py: `partial`

Every test runs against stubs. There is no real OpenTimestamps or RFC 3161 client, so
none of this is verified against a real timestamp authority.

| Test | Type | Status |
|---|---|---|
| `backdating_bound` uses `checkpoint_size > position` | unit | done |
| `claimed_at` never treated as evidence | unit | done |
| Divergence detection, triggers block attested-time rewrite | unit | done |
| **Integration against a real RFC 3161 TSA** | integration | todo |
| **Integration against a real OpenTimestamps calendar** | integration | todo |
| Receipt from a TSA whose certificate has expired since issue | security | todo |
| Malformed or hostile receipt from an anchor service | security | todo |

### publication.py: `partial`

| Test | Type | Status |
|---|---|---|
| Layout, offline verification, immutability of published checkpoints | unit | done |
| Path traversal refused in sharded hash paths | security | done |
| Refuses head going backwards, refuses divergence | unit | done |
| Anchor merge is additive | unit | done |
| Partial write: process dies mid-publication, next run recovers | operational | todo |
| Disk full during publication leaves no half-written head | operational | todo |
| Publication at tree size 1M, wall-clock and output size | load | todo |

### nearmatch.py: `partial`

| Test | Type | Status |
|---|---|---|
| Banding rules, quality cap, threshold validation | unit | done |
| `search` position filtering, `monitor` direction | unit | done |
| Alert policy limits | unit | done |
| Thresholds documented as provisional | unit | done |
| **Behaviour at `LINEAR_SCAN_ADVISORY_LIMIT` (100k rows)** | load | todo |
| Query time growth curve from 1k to 100k rows | load | todo |

### accounts.py: `partial`

| Test | Type | Status |
|---|---|---|
| scrypt parameters, salt uniqueness, verification | unit | done |
| TOTP enrolment, confirmation, single-use step enforcement | unit | done |
| `may_register_works` requires active MFA | unit | done |
| `mark_email_verified` never lowers assurance | unit | done |
| Append-only `account_events` | unit | done |
| **Timing: sign-in against a known vs unknown email is not distinguishable** | security | todo |
| TOTP clock drift, acceptance window boundaries | unit | todo |
| Password at exactly `MIN_PASSWORD_LENGTH`, and at 1MB | unit | partial |
| Unicode passwords survive normalisation round trip | unit | todo |

### sessions.py: `partial`

No dedicated test file.

| Test | Type | Status |
|---|---|---|
| Token hashed at rest, rotation on privilege change | unit | done |
| CSRF comparison is constant time | unit | done |
| TTL expiry for full and partial sessions | unit | partial |
| **Session fixation: a pre-auth token is never valid post-auth** | security | todo |
| Concurrent rotation from two requests does not orphan a session | concurrency | todo |
| Expired session cleanup does not grow unbounded | operational | todo |

### ratelimit.py: `partial`

No dedicated test file.

| Test | Type | Status |
|---|---|---|
| Buckets enforce their configured limits | unit | done |
| Window boundary: request at exactly the window edge | unit | todo |
| Clock moving backwards does not grant free attempts | security | todo |
| Table growth and pruning under sustained load | operational | todo |
| Two identities cannot share a bucket | security | todo |

### tokens.py: `partial`

| Test | Type | Status |
|---|---|---|
| Hashed at rest, single use, atomic redemption | unit | done |
| Lifetimes per purpose, issue supersedes prior token | unit | done |
| Recovery code set generation and reuse refusal | unit | done |
| **Concurrent redemption of one token by 32 threads: exactly one wins** | concurrency | todo |
| Token entropy: `TOKEN_BYTES` produces no collisions across 1M draws | security | todo |

### mail.py: `partial`

| Test | Type | Status |
|---|---|---|
| Header injection refused in `to` and `subject` | security | done |
| `no_account_message` prevents registration disclosure | security | done |
| Message bodies contain no secret beyond the link itself | security | partial |
| **`SmtpMailer` against a real SMTP server** | integration | todo |
| STARTTLS failure aborts rather than falling back to plaintext | security | todo |
| Delivery failure surfaces rather than silently dropping | operational | todo |

### domains.py and doh.py: `done`

Covered thoroughly by `test_doh.py` and `test_service.py`. One gap:

| Test | Type | Status |
|---|---|---|
| A non-https resolver endpoint is refused at construction | security | done |
| A resolver returning a valid answer for the wrong name | security | todo |

### service.py: `partial`

47 tests, mostly authorisation refusals. The HTTP layer itself is under-tested.

| Test | Type | Status |
|---|---|---|
| Session, MFA and CSRF refusals per endpoint | functional | done |
| Rate limits on sign-in, registration, domain checks | functional | done |
| Identity comes from the session, never the body | security | done |
| Security headers present on success responses | security | done |
| **Security headers present on every error response including 404 and 500** | security | todo |
| **Table-driven: the exact set of endpoints exempt from CSRF, with a reason each** | security | todo |
| Oversized request body rejected before parsing | security | todo |
| Malformed JSON, wrong content type, missing body | functional | todo |
| Method confusion: GET on a POST route, HEAD, OPTIONS, TRACE | security | todo |
| Duplicate headers, oversized headers | security | todo |
| Slow request holds the single-threaded server (documents the dev-server limit) | load | todo |
| Error responses never leak a stack trace or file path | security | todo |

### fingerprint.py: `partial`

| Test | Type | Status |
|---|---|---|
| Hash validation, distance, quality bounds | unit | done |
| **A fingerprinter that produces hashes from real images does not exist** | unit | todo |
| Python and browser fingerprinters agree on the same file | parity | todo |

### signing.py: `partial`

| Test | Type | Status |
|---|---|---|
| Ed25519 sign and verify, key hashing | unit | done |
| Every module except `signing` imports with `cryptography` absent | unit | done |
| Key rotation: old signatures still verify after a new key is active | unit | todo |
| Signer boundary holds against a KMS-backed implementation | integration | todo |

### scripts/: `todo`

Zero coverage on all three. Each has real logic.

| Test | Type | Status |
|---|---|---|
| `publish_checkpoint.py` refuses without a signing seed, exits non-zero | functional | todo |
| `publish_checkpoint.py` is idempotent when run twice in one interval | functional | todo |
| `build_demo_log.py` produces a log that the JS verifier accepts | integration | todo |
| `run_service.py` starts, serves, and shuts down cleanly | smoke | todo |
| `--dns none` reports "not checked" and never "not owned" | functional | todo |

The four legacy `cartify_*.py` and `drive_upload.py` scripts at the repository root are
excluded from linting and have no tests. They are the previous generation of the tool,
kept for provenance. Decide whether they move under `legacy/`, get deleted, or come up to
standard, rather than leaving them tracked and unowned in a public repository.

---

## 2. Cross-implementation parity

The browser verifier and the Python implementation must agree, or a record that verifies
on the site fails for someone using the library, and neither party can tell who is wrong.

| Test | Type | Status |
|---|---|---|
| `verifier.js` inclusion proofs against Python vectors (167 cases) | parity | done |
| `nearmatch.js` banding against Python (424 decisions) | parity | done |
| Malformed checkpoint rejection agrees between implementations | parity | done |
| **`verify.js` (314 lines) has no parity coverage** | parity | todo |
| Canonical JSON serialisation agrees byte for byte | parity | todo |
| Fingerprint computation agrees on identical input | parity | todo |
| Vectors regenerate deterministically and are committed | regression | partial |

---

## 3. Security

Items above marked `security` belong here too. This section is the ones that cross module
boundaries.

### Authentication and authorisation

| Test | Type | Status |
|---|---|---|
| MFA required before registering work, enforced at the write | security | done |
| Recovery code single use | security | done |
| Password reset ends every other session | security | done |
| Reset token is not spent when the new password is rejected | security | done |
| **IDOR sweep: account A cannot read or act on any of account B's resources** | security | todo |
| Assurance level cannot be raised by any client-supplied value | security | partial |
| A partial (pre-MFA) session cannot reach any full-session endpoint | security | partial |
| Sign-out invalidates server side, not only the cookie | security | todo |
| Credential stuffing: rate limit holds across many accounts from one source | security | todo |

### Injection and untrusted input

| Test | Type | Status |
|---|---|---|
| Email header injection | security | done |
| Path traversal in publication paths | security | done |
| **SQL: every query is parameterised, asserted by a source scan test** | security | todo |
| Log injection: newline in an identity or email cannot forge a log line | security | todo |
| Stored XSS: a record field containing markup renders escaped on every page | security | todo |
| JSON payload with `__proto__` or duplicate keys | security | todo |

### Cryptographic

| Test | Type | Status |
|---|---|---|
| Quorum cannot be met by the log key, or by one witness counted twice | security | done |
| Domain separation prevents a leaf being read as a node | security | done |
| Record validity requires log inclusion, not merely a valid signature | security | partial |
| Split view: two heads at one size are detected as COMPROMISED | security | partial |
| Constant-time comparison used for every secret comparison, asserted by scan | security | todo |

### Denial of service

| Test | Type | Status |
|---|---|---|
| Unbounded tree size does not recurse | security | done |
| Oversized DoH answer refused | security | done |
| Rate limit keyed to peer address, not a spoofable header | security | done |
| Algorithmic complexity: a crafted input that makes near-match search quadratic | security | todo |
| Registration flood at the rate limit ceiling, sustained | load | todo |

### Secret handling

| Test | Type | Status |
|---|---|---|
| No secret appears in any log line, at any level | security | todo |
| No secret appears in an error message returned to a client | security | todo |
| A repository scan finds no committed key material or credential | security | todo |
| `var/domain-secret` is created 0600 and never world readable | security | todo |

---

## 4. End to end

**No browser test infrastructure exists.** Sixteen pages, twenty-one JS modules, zero
automated coverage. Every page has been checked by hand at least once, which is not a
control that survives the next change.

The TDZ bug in `settings.js` that blanked the assurance ladder was caught by looking at
the rendered page. Nothing in the suite would have caught it, and nothing would catch the
next one.

| Flow | Type | Status |
|---|---|---|
| Create account, enrol MFA, confirm email, register a work, view its record | e2e | todo |
| Sign in, fail MFA, recover with a recovery code | e2e | todo |
| Forgot password, reset by emailed link, sign in with the new password | e2e | todo |
| Prove a domain: challenge, publish, check, ladder updates | e2e | todo |
| Public verify: drop a file, get each of the six verification states | e2e | todo |
| Monitoring dashboard renders alerts and their caution text per band | e2e | todo |
| Record permalink verifies inclusion in the browser, offline from the API | e2e | todo |
| Sign out clears the session and the nav reverts | e2e | todo |

| Cross-cutting | Type | Status |
|---|---|---|
| **Every page loads with zero console errors under the real CSP** | e2e | todo |
| No page makes a request the CSP would block | e2e | todo |
| Every page renders in light and dark theme | visual | todo |
| Every page is usable at 375px width | visual | todo |
| Keyboard path through every form, visible focus throughout | accessibility | todo |
| Axe or equivalent passes on every page | accessibility | todo |
| Pages that need no session still work with the API entirely down | e2e | todo |

Tooling is undecided. Playwright is the obvious choice and adds the project's first
Node dependency beyond the test runner, which is a real cost for a codebase that has
kept to the standard library. Worth deciding explicitly rather than drifting.

---

## 5. Regression and measurement

| Test | Type | Status |
|---|---|---|
| `compare()` flags precision or recall drops beyond tolerance | regression | done |
| `recommend()` refuses to derive thresholds from modelled data | regression | done |
| Per-transform and per-quality breakdowns computed | regression | done |
| **A measured corpus exists** | measurement | todo |
| **Baseline report committed, and CI fails on regression against it** | regression | todo |
| Hard negatives included: same artist, same subject, stock photography | measurement | todo |
| Recall per transform: recompress, resize, crop, rotate, watermark, screenshot | measurement | todo |
| Precision and false-positive rate per quality stratum | measurement | todo |

The harness is complete and has never run on a real image. Everything above depends on
building a fingerprinter and assembling a corpus first. See `certifiles-eval-unmeasured`
in project memory and the build order in ADR 0002.

Until a baseline exists, `TIGHT = 0.12` and `LOOSE = 0.25` are guesses shown to artists
as confidence bands.

---

## 6. Load and capacity

Nothing in this section exists.

| Test | Type | Status |
|---|---|---|
| Near-match search at 1k, 10k, 100k stored fingerprints | load | todo |
| Log append throughput, and where it falls over | load | todo |
| Publication wall-clock and output size at tree sizes to 1M | load | todo |
| Proof generation cost as the tree grows | load | todo |
| Concurrent sign-ins against the account store | load | todo |
| Memory ceiling of `loadAllEntries` in the browser as the log grows | load | todo |
| Rate limiter table growth over a simulated month | load | todo |

The browser verifier downloads the whole log to run monitoring. That is documented as not
scaling, and the point at which it stops working has never been measured.

---

## 7. Operational and failure injection

| Test | Type | Status |
|---|---|---|
| Witness unavailable: registration continues, records issue as PENDING_WITNESS | operational | partial |
| Anchor staleness beyond three intervals renders as UNVERIFIED | operational | partial |
| Two heads at one size render as COMPROMISED and preserve both | operational | partial |
| Restore every store from backup and verify integrity afterwards | operational | todo |
| Kill the service mid-append and confirm the log is consistent on restart | operational | todo |
| Clock skew: system time jumps backward and forward by an hour | operational | todo |
| Disk full during publication and during append | operational | todo |
| Schema migration against a database holding production-shaped data | operational | todo |
| Signing key rotation with records issued under both | operational | todo |
| DoH resolvers both unreachable: domain checks report not-checked, nothing else breaks | operational | todo |
| Mail delivery failing for an hour: no lost verification, no silent drop | operational | todo |

---

## 8. Supply chain and CI

`.github/workflows/ci.yml` runs on every push and on pull requests to `main`.

| Item | Status |
|---|---|
| Workflow running the Python suite on push and pull request | done |
| Python matrix covering the 3.11 floor and the 3.13 development version | done |
| Workflow running the JS cross-check | done |
| Static analysis on the Python source | done |
| Third-party actions pinned to commit SHA, not tag | done |
| Explicit minimal `permissions:` block per workflow | done |
| Linter version pinned so a new release cannot fail an unrelated commit | done |
| Dependency vulnerability scan | todo |
| Secret scanning over history, not only the working tree | todo |
| Eval regression gate once a baseline exists | todo |
| Coverage measured and reported, without a target that rewards padding | todo |
| Branch protection requiring the above before `main` | todo |

Lint rule selection is in `pyproject.toml` and is deliberately narrow: pyflakes, syntax
errors, and the flake8-bandit security set, which the codebase passes today. The remaining
default rules report about seventy findings, almost all style and typing modernisation.
Widening the selection needs a dedicated cleanup pass first, otherwise the gate fails on
its first run and gets disabled.

`bandit` itself is not run separately. Ruff's `S` rules are a port of it with matching
identifiers, and running both would mean maintaining two suppression syntaxes for the same
findings.

Secret scanning is listed as todo, but GitHub provides it natively for public repositories
as a settings toggle rather than a workflow. Turn that on rather than building a weaker
grep.

`requirements.txt` serves two codebases. `cryptography` is the only entry the certifiles
package uses, and `signing.py` imports it lazily inside a function so the rest of the
library works without it. Everything else, which is `imagehash`, `pillow`, `imageio`,
`fpdf`, `watchdog`, `requests` and four Google API clients, belongs to the four legacy
`cartify_*.py` and `drive_upload.py` scripts still tracked at the repository root.

So a dependency scan will report on packages certifiles does not ship, attributed to a
repository that does. Split the requirements file before adding a scanner, or the first
run produces findings nobody can act on and the habit of ignoring its output starts on
day one. A test asserting every declared dependency is imported somewhere would keep both
files honest afterwards.

---

## Priority

Ordered by what fails worst if left undone.

1. **CI running the two existing suites.** Everything else is optional until running tests is not.
2. **The eval corpus and baseline.** ADR 0002's build order depends on a number nobody has.
3. **E2E smoke on the critical flows.** Sixteen pages with no automated coverage, and one silent-blanking bug already found by eye.
4. **The security sweep tests**: IDOR, CSRF exemption table, headers on error responses, secrets in logs.
5. **RFC 6962 and C2SP conformance.** Correct against ourselves is not correct against other verifiers.
6. **Concurrency**: token redemption races, session rotation, sustained appends.
7. **Load**, to find where linear scan and whole-log download actually break.
8. **Operational and failure injection**, which mostly needs a staging environment that does not exist yet.

## Non-goals

- Coverage percentage as a target. It rewards testing trivial paths and says nothing about whether the tests can fail.
- Testing the standard library.
- Mutation testing as a gate. It stays a manual discipline applied when writing tests, which is how the decorative tests found so far were caught.
- Testing the demo log's contents. It is a fixture, and its correctness is whether the verifier accepts it.
