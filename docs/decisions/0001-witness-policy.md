# ADR 0001: Witness policy

Status: proposed
Date: 2026-09-04
Related: docs/architecture/threat-model-registration.md (T2, Witnessing)

## Context

Certifiles asserts that a record existed at a stated time. The attack that destroys that
assertion is backdating, and the operator is the most capable attacker: holding the log
signing key permits serving two internally consistent histories to different parties.

Independent witnesses close this by cosigning tree heads only after verifying a
consistency proof against the last head they signed. This ADR fixes the quorum rule, how
the policy changes over time, and what a verifier does when the policy is not satisfied.

The policy must be defined before the first production record exists. Records written
before a policy is in force cannot be retroactively covered by one, and a system that
cannot state its assurance at time of issue cannot report assurance honestly later.

## Decision

### Quorum

A tree head is **witnessed** when it carries the log's own signature plus at least `K`
valid cosignatures from distinct witnesses drawn from the active set `N`, where `K` and
`N` are fixed by the policy version in force at that tree size.

Independence constraints on `N`:

- Each witness is a separate legal entity, not controlled by or contracted to Certifiles.
- No witness receives payment from Certifiles for witnessing.
- No more than `K - 1` witnesses may run on any single cloud provider or in any single
  jurisdiction, so that a correlated outage or a single legal order cannot silently
  satisfy or destroy quorum.
- Witness keys are generated and held by the witness. Certifiles never possesses them.

Quorum values are staged. Launching with no cosigners is acceptable if it is stated
honestly; claiming assurance that does not exist is not.

| Stage | K | N | Gate |
|---|---|---|---|
| 0 | 0 | 0 | Anchors only (OpenTimestamps, RFC 3161, write-once store). Free tier only. |
| 1 | 1 | 2 | First external cosigner in production. |
| 2 | 2 | 4 | Required before any paid or enterprise tier is sold. |
| 3 | 3 | 7 | Target steady state. |

`K >= 2` is the point at which collusion, rather than a single compromise, becomes
necessary to forge history. No record issued under stage 0 or 1 may be marketed at the
assurance language reserved for stage 2 and above.

### Anchoring is mandatory at every stage

Anchors are not witnesses and never count toward `K`. They are required at all stages
because they bound backdating during the window before a tree head is cosigned. Anchor
cadence is hourly.

### Policy versioning

The policy is a signed document containing: version number, effective-from tree size,
`K`, the full witness set with public keys, and the independence attestation for each
witness.

Rules:

1. **The policy is logged.** Each policy version's hash is written into the log itself,
   making policy history as tamper-evident as record history. Version 1's hash is
   published to the external anchors at genesis, before any record exists.
2. **Effective-from is a tree size, not a wall-clock time.** Wall-clock is operator
   controlled; tree size is not.
3. **Every record stores the policy version in force at its tree size.** Assurance level
   is derived from that stored version, never recomputed against the current policy.
4. **Policy history is append-only.** A record's stated assurance may never be revised
   upward. Discovering later that a witness was not in fact independent lowers assurance
   for records under affected versions; it never raises it.
5. **Adding a witness takes effect at a future tree size**, announced at least one
   anchoring interval in advance, giving verifiers and monitors a public window to
   observe the change.
6. **Removing a witness requires a stated reason** — compromise, retirement, or sustained
   unresponsiveness — recorded in the policy version. Emergency removal is permitted and
   is flagged as such.
7. **Any change that lowers `K` or shrinks `N` is a downgrade event**, published as such
   and surfaced by the verifier on affected records rather than absorbed silently.

### Verifier behaviour

The verifier runs offline from published data and never upgrades a result because
Certifiles asserts something. It returns a status, not a boolean, because collapsing
these cases into pass/fail either overstates weak records or discards valid ones.

| Status | Condition | Verifier action |
|---|---|---|
| `VALID` | Inclusion proven; tree head meets `K` for its policy version | Report, with policy version and witness count |
| `VALID_UNDERWITNESSED` | Inclusion proven; cosignatures below `K` | Report, stating actual count against required `K` |
| `PENDING_WITNESS` | Inclusion proven; no witnessed head yet covers this tree size | Report as provisional, with expected coverage interval |
| `UNVERIFIED` | Data unreachable, or newest tree head older than the staleness bound | Report inability to verify; never infer validity |
| `INVALID` | Inclusion proof fails, or log signature invalid | Reject regardless of any other evidence |
| `COMPROMISED` | Two tree heads at the same size with different roots, or a failed consistency proof | Fail hard; preserve both signed heads and instruct publication |

Additional rules:

- An unknown or unparseable policy version fails closed as `UNVERIFIED`. A verifier that
  does not understand the policy must never guess.
- A cosignature from an unrecognised key, or an invalid signature from a recognised key,
  counts as absent rather than as an error, and contributes to falling short of `K`.
- `COMPROMISED` is self-authenticating: two conflicting heads under the log's key are
  non-repudiable proof of operator misbehaviour and require no trust in the reporter.
  The verifier must instruct the user to publish that evidence rather than to report it
  privately to Certifiles.
- Staleness bound is three anchoring intervals. A log that stops publishing is
  withholding, and withholding is indistinguishable from an attack in progress.

### Registration under witness unavailability

Registration does not block when witnesses are unreachable. Records are accepted and
issued as `PENDING_WITNESS`, and their assurance rises automatically once a witnessed
tree head covers their tree size.

Blocking registration would convert a witness outage into a Certifiles outage and give
any witness an unintended veto over the business. The tradeoff is an acknowledged window
during which a record is anchored but not cosigned; the anchors bound backdating within
that window, and the record's status states plainly that it is provisional.

## Consequences

**Gained.** Backdating requires collusion among independent parties rather than a single
key compromise. The operator can demonstrate structural incapacity to forge history,
which is both a defence against accusation and the strongest available marketing claim.
Assurance becomes an honest, per-record, historically accurate property.

**Cost.** Recruiting witnesses is a sustained relationship burden falling on the founder,
outside the build. Stage 2 gates revenue on that recruitment succeeding, which is a real
schedule risk that must be started early rather than deferred until a paid tier is ready.
The verifier is more complex than a boolean check, and six statuses must be explained to
non-technical users without destroying comprehension.

**Accepted.** Records issued at stage 0 carry permanently weaker assurance than later
ones. This is honest and unavoidable; the alternative is misrepresenting them. Early
users should be told at issue, not on discovery.

**Deferred.** Witness compensation is prohibited under this ADR, which limits the
candidate pool to parties with intrinsic motivation. If recruitment stalls at stage 1,
revisit whether a neutral funding structure — a foundation, or pooled funding across
several providers — preserves independence while enabling payment. Do not resolve this by
quietly paying witnesses under the existing policy.

## Open questions

- Which two organisations are the stage 1 and stage 2 targets, and what is the ask?
- Does the verifier ship as a library, a CLI, or both, and under what licence?
- What is the disclosure procedure when a verifier reports `COMPROMISED` against
  Certifiles itself, and who publishes it if the operator is the accused party?
