import { mountNav, loadManifest, escapeHtml } from "../site.js";
import { parseCheckpoint, hex, verifyQuorum } from "../verifier.js";

mountNav("status.html");
const BASE = new URLSearchParams(location.search).get("log") || "./log";
const out = document.getElementById("out");

const STALENESS_INTERVALS = 3;
const ANCHOR_INTERVAL_SECONDS = 3600;

const cell = (label, value, note) => `
  <div class="cell"><dt>${escapeHtml(label)}</dt>
    <dd>${value}${note ? `<small>${note}</small>` : ""}</dd></div>`;

const manifest = await loadManifest(BASE);
if (!manifest) {
  out.innerHTML = `<div class="callout warn"><p>The published log is unreachable. That is a
    fault on our side and says nothing about any record. If this persists, the log is
    withholding, and a log that stops publishing is indistinguishable from one under
    attack.</p></div>`;
} else {
  const checkpointBytes = new Uint8Array(
    await (await fetch(`${BASE}/checkpoint`, { cache: "no-store" })).arrayBuffer(),
  );
  const checkpoint = parseCheckpoint(checkpointBytes);

  const policyVersions = manifest.policy_versions ?? [];
  let policy = null;
  for (const version of policyVersions) {
    const candidate = await (
      await fetch(`${BASE}/policy/${String(version).padStart(6, "0")}.json`)
    ).json();
    if (BigInt(candidate.effective_from_size) <= checkpoint.size) policy = candidate;
  }
  const quorum = policy ? await verifyQuorum(checkpoint, policy) : null;

  const anchorFile = await fetch(
    `${BASE}/anchors/${String(manifest.size).padStart(12, "0")}.json`,
    { cache: "no-store" },
  );
  const anchors = anchorFile.ok ? (await anchorFile.json()).anchors : [];
  const attested = anchors.filter((a) => a.attested_at !== null);
  const newest = attested.length ? Math.max(...attested.map((a) => a.attested_at)) : null;
  const ageSeconds = newest ? Math.floor(Date.now() / 1000) - newest : null;
  const stale = newest === null || ageSeconds > ANCHOR_INTERVAL_SECONDS * STALENESS_INTERVALS;

  const agreement = hex(checkpoint.rootHash) === manifest.root_hash
    && checkpoint.size === BigInt(manifest.size);

  out.innerHTML = `
    ${!agreement ? `<div class="callout warn"><p><strong>Integrity failure.</strong> The
      manifest and the signed checkpoint disagree about this log's own head. Save both files
      and publish them.</p></div>` : ""}

    <dl class="stat">
      ${cell("Records", manifest.size)}
      ${cell("Tree head", `${manifest.root_hash.slice(0, 16)}…`, "signed root at this size")}
      ${cell("Log signature",
        quorum ? (quorum.logSigned ? "valid" : "INVALID") : "unchecked",
        policy ? escapeHtml(policy.log_key_name) : "no policy published")}
      ${cell("Witness quorum",
        quorum ? `${quorum.witnesses.length} of ${quorum.required}` : "unknown",
        policy ? `policy v${policy.version}` : "no policy published")}
      ${cell("Last attested anchor",
        newest ? new Date(newest * 1000).toISOString().replace("T", " ").slice(0, 16) : "never",
        newest ? `${Math.floor(ageSeconds / 60)} minutes ago` : "backdating is unbounded")}
      ${cell("Anchoring", stale ? "STALE" : "current",
        `tolerance is ${STALENESS_INTERVALS} intervals of ${ANCHOR_INTERVAL_SECONDS / 60} minutes`)}
    </dl>

    ${stale ? `<div class="callout warn"><p><strong>Anchoring is stale.</strong> No anchor has
      been attested within the tolerated window. Backdating is bounded only as far back as the
      last attested anchor, and a log that stops anchoring is withholding.</p></div>` : ""}

    ${quorum && quorum.required === 0 ? `<div class="callout"><p>This log runs at
      <strong>stage 0</strong>: anchors only, no witnesses recruited. Backdating is bounded by
      the anchor, and nothing independent prevents the operator from serving two histories.
      Records issued now will always carry that weaker assurance, honestly reported.</p></div>`
      : ""}

    <h2>Why this page exists</h2>
    <div class="prose">
      <p>A service that asks you to trust its records and hides its own operating state is
        asking for trust rather than earning it. Everything above is computed in your browser
        from the published files. You can compute it yourself:</p>
      <pre>curl -s ${escapeHtml(location.origin)}/log/manifest.json
curl -s ${escapeHtml(location.origin)}/log/checkpoint</pre>
      <p>The number that matters most is the witness quorum. Anchors bound how far back a
        record can be dated; only independent witnesses stop the operator serving one history
        to you and a different one to someone else.</p>
    </div>`;
}
