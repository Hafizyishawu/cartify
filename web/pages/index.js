import { verifyFingerprint, hashFile, isContentHash } from "../verify.js";
import { Status } from "../verifier.js";
import { mountNav } from "../site.js";
mountNav("index.html");

const BASE = new URLSearchParams(location.search).get("log") || "./log";

const RAIL = {
  [Status.VALID]: "proven", [Status.VALID_UNDERWITNESSED]: "partial",
  [Status.PENDING_WITNESS]: "pending", [Status.NO_RECORD]: "unknown",
  [Status.UNVERIFIED]: "unknown", [Status.INVALID]: "invalid",
  [Status.COMPROMISED]: "compromised",
};
const LABEL = {
  [Status.VALID]: "Recorded and witnessed",
  [Status.VALID_UNDERWITNESSED]: "Recorded, lightly witnessed",
  [Status.PENDING_WITNESS]: "Recorded, awaiting witnesses",
  [Status.NO_RECORD]: "No record found",
  [Status.UNVERIFIED]: "Cannot check right now",
  [Status.INVALID]: "Record does not check out",
  [Status.COMPROMISED]: "Log integrity failure",
};

const el = (id) => document.getElementById(id);
const working = (text) => {
  el("working").textContent = text;
  el("working").classList.toggle("hidden", !text);
};

function render(result, fingerprint) {
  const claim = result.claims?.[0];
  const status = result.status;
  const record = claim?.record;
  const issuer = record?.issuer;

  // A record-level failure carries its detail on the claim, not on the result.
  // Reading only the latter left the most important failure states, a forged
  // record or a missing proof, showing a status label with no explanation.
  const verdict = record
    ? `Registered by ${issuer.identity_id} at position ${claim.position}.`
    : result.detail ?? claim?.detail ?? "This record could not be verified.";

  const notProven =
    "That the registrant created the work, or that it is not AI-generated. " +
    "Certifiles records a claim and the time it was made. It does not adjudicate authorship.";

  el("out").innerHTML = `
    <div class="result">
      <div class="rail" style="background:var(--${RAIL[status]})"></div>
      <div class="inner">
        <div class="state" style="color:var(--${RAIL[status]})">${LABEL[status]}</div>
        <div class="verdict">${escape(verdict)}</div>
        <dl class="rows">
          ${record ? `<div class="row"><dt>Proven</dt><dd>${escape(claim.detail)}</dd></div>` : ""}
          ${!record && claim ? `<div class="row"><dt>Position</dt><dd>${claim.position}</dd></div>` : ""}
          ${record ? `<div class="row"><dt>Not proven</dt><dd>${notProven}</dd></div>` : ""}
        </dl>
        <dl class="facts">
          <div class="fact"><dt>Fingerprint</dt><dd>${escape(fingerprint.slice(0, 16))}…</dd></div>
          ${result.manifest ? `<div class="fact"><dt>Log size</dt><dd>${result.manifest.size}</dd></div>` : ""}
          ${issuer ? `<div class="fact"><dt>Assurance</dt><dd>${escape(issuer.assurance_level)}</dd></div>` : ""}
          ${result.quorum ? `<div class="fact"><dt>Witnesses</dt><dd>${result.quorum.witnesses.length} of ${result.quorum.required}</dd></div>` : ""}
        </dl>
        ${result.claims && result.claims.length > 1
          ? `<p class="drop-sub" style="margin-top:12px">Also claimed at position${
              result.claims.length > 2 ? "s" : ""} ${
              result.claims.slice(1).map((c) => c.position).join(", ")
            }. The log records claims; priority is the earliest position.</p>`
          : ""}
      </div>
    </div>`;
  el("cli").textContent = `certifiles verify --fingerprint ${fingerprint} --offline`;
}

function escape(text) {
  const node = document.createElement("div");
  node.textContent = text ?? "";
  return node.innerHTML;
}

async function lookup(fingerprint) {
  working("checking the published log…");
  try {
    render(await verifyFingerprint(BASE, fingerprint), fingerprint);
  } catch (error) {
    render({ status: Status.UNVERIFIED, detail: `Could not complete the check: ${error.message}` },
           fingerprint);
  }
  working("");
}

el("form").addEventListener("submit", (event) => {
  event.preventDefault();
  const value = el("hash").value.trim().toLowerCase().replace(/^sha256:/, "");
  if (!isContentHash(value)) {
    render({ status: Status.INVALID, detail: "That is not a SHA-256 fingerprint: 64 hex characters are expected." }, value || "nothing");
    return;
  }
  lookup(value);
});

async function handleFile(file) {
  working(`hashing ${file.name} in your browser…`);
  const fingerprint = await hashFile(file, (p) => working(`hashing ${file.name}… ${Math.round(p * 100)}%`));
  el("hash").value = fingerprint;
  await lookup(fingerprint);
}

el("drop").addEventListener("click", () => el("file").click());
el("drop").addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); el("file").click(); }
});
el("file").addEventListener("change", (e) => e.target.files[0] && handleFile(e.target.files[0]));
for (const type of ["dragenter", "dragover"]) {
  el("drop").addEventListener(type, (e) => { e.preventDefault(); el("drop").classList.add("over"); });
}
for (const type of ["dragleave", "drop"]) {
  el("drop").addEventListener(type, (e) => { e.preventDefault(); el("drop").classList.remove("over"); });
}
el("drop").addEventListener("drop", (e) => e.dataTransfer.files[0] && handleFile(e.dataTransfer.files[0]));

const preset = new URLSearchParams(location.search).get("q");
if (preset) { el("hash").value = preset; lookup(preset.toLowerCase()); }
