# Threat model: Certifiles registration and verification

Status: draft
Date: 2026-09-04
Scope: the registration flow (content submitted, provenance record issued) and the
verification flow. The two are modelled together because a registration guarantee that
cannot be independently verified is not a guarantee.

Out of scope for this pass: billing, the dispute and prior-art tier, and the
transaction-ledger product.

---

## What the system claims

Certifiles asserts exactly one thing, and the threat model exists to protect it:

> At time T, identity I asserted authorship of content with hash H, and that assertion
> was entered into a public append-only log.

It does not claim the content is original, human-made, lawful, or that I is who they
say they are beyond the assurance level recorded. Every threat below is a way to make
that sentence false, unprovable, or unfalsifiable.

## Trust boundaries

| Boundary | From | To | Carries |
|---|---|---|---|
| B1 | Untrusted client | Registration API | Content hash, claims, session |
| B2 | Registration API | Signing service (KMS) | Manifest to be signed |
| B3 | Registration API | Transparency log | Signed manifest |
| B4 | Transparency log | Public witnesses | Signed tree head |
| B5 | Anyone | Verification API | Hash or file to check |

B4 is the boundary most systems of this kind omit, and its absence is what makes
"append-only" a promise rather than a proof.

## Assets, by blast radius

| Asset | Compromise impact | Recoverable |
|---|---|---|
| Signing key | Every record ever issued becomes forgeable, retroactively | No |
| Log append-only property | Backdating; the core claim becomes worthless | No |
| Identity binding | Records attribute to the wrong actor | Partially |
| Verification endpoint honesty | All claims become unfalsifiable | Yes |
| Record corpus availability | Existing proofs cannot be presented | Yes, if mirrored |
| User PII | Regulatory exposure, deanonymisation of pseudonymous creators | No |

The top two rows end the business. Everything else is an incident. Control investment
should be weighted accordingly, and the first two rows should be addressed by design
rather than by detection.

---

## T1. Signing key compromise

**Actor:** external attacker with API/infra foothold, or a malicious insider.
**Goal:** mint valid records offline, with arbitrary content, identity and timestamp.

Paths: key exfiltrated from application memory or config; insider uses standing KMS
access to sign off-ledger; compromised CI/CD ships code that signs attacker-supplied
manifests; over-broad IAM lets an unrelated workload call the signing key.

**Structural control — make a stolen key insufficient.** A signature alone must never
constitute a valid record. Validity is defined as *inclusion in the log*, proven by an
inclusion proof against a witnessed tree head. A stolen key then produces records that
fail verification because they were never logged, which converts key compromise from
unrecoverable to serious. This single definitional choice does more than any perimeter
control, and it must be in the verification spec from the first release.

Supporting controls: non-exportable KMS or HSM keys; signing available only to a
dedicated service with its own identity, never to the general API role; no standing
human access, break-glass only, time-limited and audited; published key history so
rotation does not invalidate old records; alerting on any signing call that does not
have a corresponding log append within seconds.

## T2. Log backdating

**Actor:** insider with database access, or an attacker who has reached the datastore.
**Goal:** insert a record bearing an earlier timestamp, proving prior creation.

This is the highest-value attack on the entire product. Ownership disputes are decided
by who was first, so the ability to move backwards in time *is* the ability to steal any
work in the system.

An append-only table in PostgreSQL is not append-only; it is a table that the current
schema declines to update. Anyone with sufficient privilege rewrites it silently.

**Controls:** Merkle tree log with signed tree heads. Publish tree heads at a fixed
cadence to multiple *independent* witnesses — third-party cosigners, an RFC 3161
timestamping authority, and a write-once store such as S3 with Object Lock in a separate
account with a separate trust domain. Serve consistency proofs so any client can verify
the log has never forked. Absent external witnesses, the operator can always rewrite
history, and the system's guarantee reduces to "trust Certifiles."

Note the ordering dependency: witnessing must exist before the first record is written,
because records created before witnessing began can never be retroactively proven
un-backdated.

Witnessing is the load-bearing control for this threat and is specified in full in
"Witnessing" below, and in ADR 0001.

## T3. Mass pre-emptive registration

**Actor:** opportunistic squatter or extortionist.
**Goal:** scrape public portfolios and register works at volume, then monetise the claim.

Accepted product position is that the burden of timely registration sits with the
author. That position holds for one work and fails for one million: a squatter holding
the registered claim to a large body of scraped work is a business-ending news story
regardless of where the burden formally sits, because the affected authors were not slow
— the service did not yet exist.

**Controls:** per-account and per-IP rate limits on registration; non-zero marginal cost
per record; anomaly detection on bulk submission and on submission velocity that exceeds
plausible human creation; reverse-pHash screening of new registrations against a corpus
of known public work, flagging rather than blocking; reserve the highest assurance tier
for capture-attested content (C2PA), which a scraper cannot produce; and a documented
prior-art dispute tier so the answer to a journalist is a process, not a shrug.

## T4. Identity spoofing and account takeover

**Actor:** external attacker, or anyone at signup.
**Goal:** register as someone else, or seize an account holding valuable records.

Email-only identity means email compromise is identity compromise, and nothing at signup
prevents an account presenting as a known studio or agency.

**Controls:** mandatory MFA on any account holding records; verified-organisation tier
gated on domain control (DNS TXT or an address at the domain); the assurance level must
be a first-class field displayed on every record and returned by the verification API,
never inferred; screening of display names against high-profile entities at the verified
tier; full audit trail on account recovery, since recovery is the softest path to every
record an account holds.

Account recovery deserves specific attention: it is the one flow that intentionally
grants control to someone who has lost their credentials, and it will be the most
attacked surface in the product.

## T5. Verification-side attacks

**Actor:** anyone presenting a forged claim to a non-technical audience.
**Goal:** be believed without holding a valid record.

If the trust signal is a badge image or a screenshot of a results page, forgery is a
screenshot edit. This is precisely how trust seals and EV certificate indicators failed:
the signal was visual and the verification was nobody's job.

Related: denial of service against the verification endpoint. If verification is
unavailable, claims cannot be checked, and an unfalsifiable claim favours the forger.

**Controls:** verification must be independently computable offline from the published
tree head and an inclusion proof, with an open-source verifier that does not call
Certifiles infrastructure. The website is a convenience, never the proof. Verification
must be public, free and unauthenticated, or third parties will not check and the
guarantee decays into a brand claim. Monitor for lookalike and homoglyph domains hosting
counterfeit verifiers.

## T6. Hash-layer attacks

SHA-256 over exact bytes is sound; the exposure is at the perceptual layer.

Perceptual hashes are adversarially malleable. An attacker can craft an image that
collides with a target pHash, or perturb a copy so it does not match. Therefore pHash
must never carry evidentiary weight. Its only legitimate role is as a search hint that
surfaces candidates for human dispute review, and the API and UI must not present it as
proof of anything.

Prohibit MD5 and SHA-1 anywhere in the manifest or the log, including in any imported
legacy Cartify record.

## T7. Availability and company mortality

The product promises permanence, and a startup is not permanent. Every serious buyer
will ask what happens to their proof if Certifiles shuts down, and "we won't" is not an
answer.

**Control, which is also a feature:** periodically publish the complete log — hashes,
manifests, signatures, tree heads — to durable independent storage that survives the
company. Records then remain verifiable by anyone with the published data and the open
verifier, with no live service involved. This converts the strongest adoption objection
into the strongest differentiator.

## T8. Abuse, takedown and the erasure conflict

Storing only hashes and never content removes most illegal-content and copyright
custody exposure, and is the single largest liability reduction available. Take it.

An unresolved conflict remains: an append-only log cannot honour a GDPR erasure request,
and pseudonymous creators may be deanonymised by their own record history.

**Control:** no personal data in the log, ever. The log entry references an identity by
opaque, stable identifier; the mutable identity record lives in a conventional database
where erasure is possible. Erasure then breaks the human-readable attribution while
leaving the cryptographic history intact. Records cannot be deleted, only superseded by
a later revocation or dispute entry, and this must be stated plainly in the terms before
launch rather than discovered during a complaint.

---

## Witnessing

The control for T2, in detail. The witness policy itself — quorum, versioning and
verifier behaviour — is specified in ADR 0001.

### Why the operator cannot witness itself

A Merkle tree prevents editing history. It does not prevent keeping two histories.
Certifiles holds the log signing key, so Certifiles can sign tree head A for one party
and tree head B for everyone else, each internally consistent, each serving valid
inclusion proofs. This is a split-view attack, and no property of the tree detects it.
Certificate Transparency encountered exactly this, which is why its design includes
auditors and gossip rather than a log alone.

Without external parties, the system's guarantee degrades to "trust the operator,"
which is the proposition Certifiles exists to replace.

### What a witness does

The role is deliberately minimal. A witness stores one item of state: the last tree head
it signed. When offered a new tree head it verifies a consistency proof from the stored
head to the new one, and cosigns only if the proof holds.

A witness does not store the log, see submitted content, evaluate claims, or process
personal data. It enforces one property: this log has only ever grown, and there is only
one of it.

The narrowness of the role is the recruitment argument. Witnesses are not asked to
endorse Certifiles or vouch for its users; they are asked to spend seconds of CPU per
interval holding the operator accountable.

### Anchors available without counterparties

These bound backdating from day one and require no agreement with anyone:

- **OpenTimestamps** — commitments aggregated into Bitcoin, free and mature. One
  commitment per interval, not per record. This does not contradict the decision not to
  build the log on a blockchain: the log remains a conventional Merkle tree and the
  chain serves only as a timestamp beacon under no single party's control.
- **RFC 3161 timestamping authorities** — DigiCert, Sectigo, FreeTSA. Inexpensive, and
  the resulting token carries a commercially recognised certificate, which matters if a
  record is presented in a legal proceeding.
- **Write-once storage in a separate trust domain** — object storage under compliance
  lock, in a distinct account with distinct root credentials and ideally a distinct
  organisation.

These establish a floor: no record can be moved earlier than the last anchor. They do
not detect forks. A timestamping authority will timestamp two divergent tree heads
without objection, so anchors are a prerequisite for witnessing, not a substitute.

### Candidate cosigners

- **The transparency-log community.** Sigsum is designed on the premise that the log is
  untrusted and witnesses supply the guarantee; a C2SP witness protocol specification and
  the Armored Witness hardware effort exist alongside it. These operators already run
  this infrastructure. Verify current status directly, as this area moves quickly.
- **Memory institutions.** Internet Archive, national libraries, university digital
  humanities departments. Mission-aligned with durable provenance of creative work, and
  institutionally longer-lived than any startup.
- **Creator-side bodies.** Photography associations, collecting societies, journalism
  organisations already committed to provenance through C2PA. Their members are the user
  base; witnessing costs them nothing and grants a governance role.
- **Competing providers.** Reciprocal witnessing between provenance services is rational
  for all parties: near-zero cost, and each gains credibility neither can manufacture
  alone.

### Two failure modes of witnessing itself

A witness funded by Certifiles is not independent. Funding the full witness set
reconstitutes self-trust with additional steps. Independence must hold across incentive,
not only infrastructure.

A cosignature that no client checks is decorative. The verifier must enforce the policy
and fail closed, and creators require a monitoring capability that watches the log for
records claiming their work. Witnessing without verification is theatre.

### Cadence

Backdating granularity equals the witness interval. Hourly anchoring is inexpensive
given OpenTimestamps aggregation and TSA pricing, and is fine-grained enough that
priority disputes rarely fall inside a single window. Daily is too coarse to defend.

### Secondary benefit

Witnessing protects users from the operator, and in doing so protects the operator. An
accusation that Certifiles backdated a record for a paying customer is answered by
demonstrating structural incapacity rather than by assertion. "You do not have to trust
me" is the strongest available claim for a provenance service, and witnessing is what
makes it true.

---

## Residual risks accepted

- First-to-register for individual works, per product decision, mitigated but not closed
  by T3 controls and the prior-art tier.
- Certifiles cannot determine whether content is AI-generated. The system records
  attestations; it does not detect. Absence of a record proves nothing, and marketing
  must never imply otherwise.
- Assurance is capped by the weakest identity tier a record was issued under.

## Control priority for v1

1. Define record validity as log inclusion, not signature. Costs nothing now, impossible
   to retrofit.
2. External witnessing of tree heads before the first production record exists.
3. Identity-ready manifest schema: issuer, key ID, assurance level, claim type.
4. Hash-only storage, no content custody.
5. Public unauthenticated verification plus an open-source offline verifier.
6. KMS-backed signing with no standing human access.
7. Registration rate limits and bulk-submission anomaly detection.
8. Mandatory MFA and an audited account-recovery flow.

Items 1, 2 and 3 are ordering-dependent: each becomes materially harder or impossible
once records exist in production.

## Open questions

- Who are the initial independent witnesses, and will any of them cosign for free?
- Does the highest assurance tier require C2PA capture attestation at launch, or later?
- What is the legal entity's stated position when a registered claim is contested in
  court, given the system attests to an assertion rather than to authorship?
