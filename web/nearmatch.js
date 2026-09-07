// Near-match banding in the browser, mirroring certifiles/nearmatch.py.
//
// Fingerprints live inside the record, so they are covered by the inclusion
// proof. That means a browser can run this search over verified data rather
// than trusting a server's similarity score. The operator cannot quietly
// revise the numbers an artist is searching on.
//
// The cost is that it reads every published entry, which is fine for a small
// log and will not stay fine. A server-side index takes over long before the
// download does, and the honest limit is stated in the interface rather than
// discovered.
//
// Nothing here returns a verdict. It returns candidates with their raw
// distances and a band that says how much attention each deserves. A false
// positive is an accusation handed to an artist about someone who did nothing,
// which is not symmetric with a missed match they can search for again.

export const BIT_LENGTHS = { phash: 64, dhash: 64, pdq: 256 };

// Provisional, matching the Python constants. Guesses, not measurements: the
// eval harness is what turns them into numbers worth defending, and until it
// runs on real images no accuracy claim built on them is founded.
export const TIGHT = 0.12;
export const LOOSE = 0.25;
export const LOW_QUALITY_CEILING = 35;

export const Band = Object.freeze({
  STRONG_CANDIDATE: "strong_candidate",
  POSSIBLE: "possible",
  WEAK: "weak",
});

const ORDER = { strong_candidate: 0, possible: 1, weak: 2 };

export function distance(a, b) {
  if (a.length !== b.length) throw new Error("fingerprints of different widths");
  let bits = 0;
  for (let i = 0; i < a.length; i += 1) {
    let x = parseInt(a[i], 16) ^ parseInt(b[i], 16);
    while (x) {
      bits += x & 1;
      x >>= 1;
    }
  }
  return bits;
}

/**
 * Band a set of distances, or null when nothing is close enough to show.
 *
 * Agreement across independent algorithms is what separates a candidate from a
 * coincidence: one hash being close is ordinary, two agreeing is not. Quality
 * caps the band regardless of distance, because a low-detail image collides by
 * coincidence far more often than a photograph.
 */
export function classify(distances, quality, tight = TIGHT, loose = LOOSE) {
  const kinds = Object.keys(distances);
  if (kinds.length === 0) return { band: null, qualityCapped: false };

  const normalised = kinds.map((k) => distances[k] / BIT_LENGTHS[k]);
  const withinTight = normalised.filter((n) => n <= tight).length;
  const withinLoose = normalised.filter((n) => n <= loose).length;

  let band;
  if (withinTight >= 2) band = Band.STRONG_CANDIDATE;
  else if (withinTight >= 1 || withinLoose >= 2) band = Band.POSSIBLE;
  else if (withinLoose >= 1) band = Band.WEAK;
  else return { band: null, qualityCapped: false };

  if (quality < LOW_QUALITY_CEILING && band !== Band.WEAK) {
    return { band: Band.WEAK, qualityCapped: true };
  }
  return { band, qualityCapped: false };
}

const closest = (distances) =>
  Math.min(...Object.entries(distances).map(([k, d]) => d / BIT_LENGTHS[k]));

/**
 * Candidates in `entries` resembling `subject`, most attention-worthy first.
 *
 * `afterPosition` restricts to later registrations, which is the monitoring
 * direction: an artist is alerted about work registered after theirs, since
 * something registered earlier cannot be a copy of it.
 */
export function search(subject, entries, { afterPosition = null, limit = 25 } = {}) {
  const mine = subject.content?.fingerprints ?? {};
  if (Object.keys(mine).length === 0) return [];

  const candidates = [];
  for (const entry of entries) {
    if (entry.position === subject.position) continue;
    if (afterPosition !== null && entry.position <= afterPosition) continue;
    if (entry.record.issuer.identity_id === subject.record.issuer.identity_id) continue;

    const theirs = entry.record.content?.fingerprints ?? {};
    const distances = {};
    for (const kind of Object.keys(mine)) {
      if (theirs[kind]) distances[kind] = distance(mine[kind], theirs[kind]);
    }
    if (Object.keys(distances).length === 0) continue;

    // The lower of the two qualities governs: comparing a detailed work
    // against a flat one is only as reliable as the flat one.
    const quality = Math.min(
      subject.content.quality ?? 100,
      entry.record.content?.quality ?? 100,
    );
    const { band, qualityCapped } = classify(distances, quality);
    if (!band) continue;
    candidates.push({ entry, band, quality, distances, qualityCapped });
  }

  candidates.sort(
    (a, b) =>
      ORDER[a.band] - ORDER[b.band] ||
      closest(a.distances) - closest(b.distances) ||
      a.entry.position - b.entry.position,
  );
  return candidates.slice(0, limit);
}

export const BAND_LABEL = {
  [Band.STRONG_CANDIDATE]: "Strong candidate",
  [Band.POSSIBLE]: "Possible",
  [Band.WEAK]: "Weak candidate",
};

export const BAND_RAIL = {
  [Band.STRONG_CANDIDATE]: "partial",
  [Band.POSSIBLE]: "pending",
  [Band.WEAK]: "unknown",
};
