# ADR 0002: Physical tags and custody

Status: proposed
Date: 2026-09-08
Related: ADR 0001 (witness policy), docs/architecture/threat-model-registration.md

## Context

Certifiles registers digital files. Physical art is where provenance already carries
commercial weight: resale, insurance, auction, estate. Extending the log to physical
objects means putting a scannable tag on the work and deciding what that tag is allowed
to claim.

Two things must be settled before a single tag exists in the world. The schema
underneath it, because an object outlives the software and cannot be re-tagged at scale.
And what the tag proves, because a physical object that implies a security property the
system does not have is worse than no tag at all: a buyer reasoning correctly from the
affordance reaches a wrong conclusion.

This ADR fixes the work and instance model, the two tiers of tag, the custody key
lifecycle, and the privacy position on scanning.

## Decision

### Work and instance are separate entities

The record schema splits in two.

A **work** is the authorship claim. One per artwork. It carries the fingerprints of the
reference photograph, the metadata, and the issuer's identity and assurance level at time
of issue. This is what enters the transparency log and what ADR 0001 governs.

An **instance** is one physical object. It points at a work and carries its own tag. An
edition of one produces one instance; an edition of fifty produces fifty instances
against a single work.

The invariant: **authorship attaches to works and never to instances. Custody attaches to
instances and never to works.** Nothing about who holds an object may alter the record of
who made it.

### Two tiers, one physical artifact

| | Reference tag | Custody tag |
|---|---|---|
| Encodes | Instance URL | Instance URL |
| Secret on the object | None | None |
| Custody chain | No | Yes |
| Transfers and claiming | No | Yes |
| Tier | Included | Premium |

The printed artifact is identical. The difference is entirely a property of the instance
record, so upgrading an instance is a server-side change and never a re-labelling
exercise.

**Certifiles never prints, ships, or embeds a secret on a physical object.** Every secret
in this design is minted on screen for one party. This is what removes the tamper-evident
seal and everything attached to it: an artist self-printing labels cannot leak a code
that was never on the label.

A consequence worth stating plainly: the free tier is strictly simpler and strictly safer
than the paid one, because every secret lives in the paid tier.

### What a tag proves

Scanning resolves to a public page asserting exactly this: a record exists, describing an
object that looks like the reference photograph, registered by this identity at this
assurance level on this date, with an inclusion proof the reader's browser verifies
locally.

It does **not** assert that the object in front of the reader is that object. A QR can be
photographed and applied to anything. The reference photograph and a human comparing it
to the object are the control, and the page must say so in the register the verify page
already uses.

For editions the limit is sharper. A counterfeit print of the same image will match the
reference photograph, so the reference tier proves the image and the artist, not the
individual copy. Distinguishing copies requires the custody chain, and that is the real
boundary between the tiers.

### Scanning records nothing about the scanner

No IP-derived location, no identity, no count attributed to a person, no alert to the
artist or custodian. A public scan is a lookup.

Three reasons, any one of which is sufficient. The scanner has not consented and is
usually a third party: a gallery visitor, a collector in their own home. IP-derived
location is personal data, and disclosing a third party's location to an artist has no
lawful basis. And it is a stalking primitive, most obviously when an artist and a
collector are in dispute.

It also inverts the product's own claim. A system whose pitch is that you need not trust
the operator must not silently geolocate people who scan it.

The monitored events are custody events instead: voluntary, authenticated, and between
parties who are in the system by choice.

### Custody key lifecycle

Minted when an account takes custody of an instance. Shown once. Stored hashed, the same
construction `tokens.py` already uses for recovery codes.

It is a **bearer key**. Whoever holds it may initiate a transfer of that instance, with or
without the custodian's account. That is what gives an heir a path when the account is
gone and the key was preserved.

It is **consumed on transfer initiation**, and the recipient's claim mints a fresh one. So
at any moment the live key is known only by the current custodian, and every previous
custodian holds a spent one. A seller cannot reclaim what they sold.

There is **no recovery**. Certifiles cannot reissue a lost key, because any path that
reissues one is an impersonation path. Storage is the holder's responsibility, and the
product states the options and ranks them: a password manager or a safe is appropriate;
writing the key on the work itself is the weakest option available, because anyone who
photographs the back can then move custody. It is offered and warned about in the same
breath.

### Transfers are two-sided and always addressed

The initiator presents the key. The recipient proves control of an email address and
holds an account at `email` assurance or above.

- The log entry is written at initiation, so the seller is discharged at the moment of
  sale rather than at the buyer's convenience.
- **Notice is the substitute for recovery.** The current custodian is alerted the instant
  a transfer is initiated, with a window to cancel before it completes. This converts
  silent key theft into something the owner can catch, without any custodial rescue path.
- If the recipient does not claim within ninety days, custody reverts to the initiator and
  a fresh key is issued to them. Otherwise a stalled transfer leaves the seller with
  neither custody nor a usable key.

Certifiles will not record a transfer with no destination. Every recorded sale is
addressed, so the chain has no anonymous gaps.

An artist may separately record that an instance left their possession without a
transfer. That is a self-declaration carrying the weight of `declared_created_at`: no
evidential value, and it does not move custody.

### Claiming is mandatory, and the mandate is commercial

No software can compel a buyer who walked away with a canvas under their arm. What the
system enforces is that the compliant path is the only one it will record. The mandate
itself lives in how artists and galleries sell.

### Unclaimed renders as anomalous

Within the custody tier, an instance with a pending or expired transfer is a real signal
and renders as a distinct state.

This reverses an earlier position that absent custody should render as silence. That
position was downstream of buyers being optional, and it no longer holds.

The distinction that survives: a reference-tier instance has no custody layer, and that is
not an anomaly and must not be styled as one. A custody-tier instance with a gap is.

### Stolen state

The custodian flags an instance from their account. The log takes the entry and the record
page shows it publicly and prominently, because publicity is the entire point in that
case.

No claim or transfer succeeds against a flagged instance. Attempts are refused, logged,
and alerted to the custodian. A claim attempt on a stolen work is the highest-value alert
this system produces.

### Build order

Bulk registration and near-match alert quality ship before durable labels or any other
premium fulfilment.

Two reasons. The volume tier is the volume user and the reason anyone hears about the
product, and tiers like this rot predictably toward wherever the interesting engineering
is. And at two hundred works per artist the near-match false positive rate stops being
academic: one noisy alert a week trains someone to ignore alerts, at which point the
monitoring is decorative. The eval harness exists and has not been run against real images
at that scale.

## Consequences

**Gained.** A physical object acquires a verifiable link to a witnessed record without
Certifiles ever holding or printing a secret that travels with it. Custody rotates such
that only the current holder knows the live key. The free tier is safer than the paid one
rather than a degraded version of it. Tag artwork is tier-independent, so the upgrade path
requires no physical intervention.

**Cost.** Bearer keys with no recovery will lose people their custody access, and that is
a support burden and a reputational one. It is the price of having no impersonation path,
and the notice-and-cancel window is the only mitigation offered. Custody friction makes
the premium tier unsuitable for low-value editions, which narrows the paid market to
high-value single works. Mandatory claiming depends on sales practice, which Certifiles
does not control.

**Accepted.** A QR can be photographed and applied to a counterfeit; the tag never claims
otherwise and the human comparison is the control. For editions, the reference tier cannot
distinguish individual copies. A lost custody key is unrecoverable. An owner who writes
the key on the work has voluntarily reintroduced the exposure this design removes, and is
warned rather than prevented.

**Deferred.** Durable printed labels as a physical product, with no security role under
this ADR since nothing secret is printed. Aggregate scan geography at country level above
a k-anonymity threshold, disclosed before recording, if it is ever wanted.

## Open questions

- Who may clear a stolen flag, and what prevents a malicious flag by a former custodian
  who still resents the sale?
- Does the artist retain standing on an instance after transferring custody? Being alerted
  that a work they made was flagged stolen seems valuable and is not obviously theirs to
  receive.
- Should the log record which edition numbers exist, so that a "62/50" is catchable at the
  reference tier without a custody chain?
- What is the upgrade path for an instance registered at the reference tier that later
  needs custody, given that the artist may no longer hold the object?
