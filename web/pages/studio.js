import { mountNav, escapeHtml as esc } from "../site.js";
import { me } from "../api.js";
import { agreesWithPublished, verifyPosition } from "../verify.js";
import { BAND_LABEL, BAND_RAIL, BIT_LENGTHS, Band, LOW_QUALITY_CEILING } from "../nearmatch.js";
mountNav("studio.html");

// Whose dashboard this is comes from the session, never from the URL. An
// earlier version read ?identity= against the public log, which meant the query
// string was the only thing scoping it and anyone could read anyone's view.
const account = await me();
const out = document.getElementById("out");
const who = document.getElementById("who");

if (!account.signed_in) {
  who.textContent = "";
  out.innerHTML = `<div class="callout"><p>Monitoring belongs to an account.
    <a href="./sign-in.html">Sign in</a> to see yours.</p></div>`;
} else {
  who.textContent = account.identity_id;
  render(await (await fetch("/api/monitoring", { credentials: "same-origin" })).json());
}

// The similarity search moved to the server, because doing it here meant
// downloading every record in the log and that stops working long before the
// log gets interesting. What did not move is the evidence. The server names
// positions; the browser proves those records are in the log, because a
// similarity score is a hint and an inclusion proof is a fact.
async function verifyNamed(matches) {
  const results = new Map();
  await Promise.all(matches.map(async ({ candidate_position: position, candidate }) => {
    try {
      const proof = await verifyPosition("./log", position);
      results.set(position, agreesWithPublished(proof, candidate.content_hash));
    } catch {
      results.set(position, agreesWithPublished(null));
    }
  }));
  return results;
}

const distanceCells = (d) => Object.entries(d)
  .map(([k, v]) => `<div><span>${esc(k)}</span>${v} / ${BIT_LENGTHS[k]}</div>`).join("");

const quality = (value) => (value == null ? "not established" : `${value}/100`);

// The wording has to match the band. Saying "the similarity fingerprints agree"
// on a weak candidate overstates the evidence, which is the failure this whole
// design is built to avoid: a false positive is an accusation handed to someone
// who did nothing.
function cautionFor(match) {
  const closeness = "That is similarity, not proof: visual coincidence happens, and the "
    + "measure can be evaded deliberately.";
  if (match.quality_capped) {
    return `Downgraded despite a close distance. The less detailed of these two images
      scores ${match.quality}/100, below the ${LOW_QUALITY_CEILING} floor, and low-detail
      images collide by coincidence far more often than photographs. Most alerts like
      this one are nothing.`;
  }
  if (match.quality == null) {
    return `Detail level was not recorded for one of these, so the low-detail safety
      check could not run. A close distance between two simple images means much less
      than it does between two photographs. ${closeness}`;
  }
  if (match.band === Band.STRONG_CANDIDATE) {
    return `Independent algorithms agree on this, which is what separates a candidate
      from a coincidence. ${closeness} Look at both before you act.`;
  }
  if (match.band === Band.POSSIBLE) {
    return `Close on some measures and not others, so this is worth a look rather than
      a conclusion. ${closeness}`;
  }
  return `Only one measure puts these near each other, and the rest do not. Most alerts
    at this level are nothing; it is here so you can see it, not because it is likely.`;
}

function provenance(data, proofs) {
  if (!data.searched) {
    // An index that is not there did not search and find nothing. Saying "no
    // matches" would tell an artist they are safe on the strength of a search
    // nobody ran.
    return `<p class="notice warn">The near-match index is not available, so no search
      ran. This is not the same as finding nothing, and says nothing about whether
      anything resembling your work has been registered.</p>`;
  }
  const states = [...proofs.values()].map((p) => p.state);
  const verified = states.filter((s) => s === "verified").length;
  const mismatched = states.filter((s) => s === "mismatch").length;
  const note = mismatched
    ? `<p class="notice warn"><strong>${mismatched} of these do not match the published
       log.</strong> The server named a record that the published log does not hold at
       that position. Do not act on the results below; this is the disagreement the
       published log exists to make visible.</p>`
    : "";
  return `${note}<p class="notice">Searched server-side over ${data.log_size}
    record${data.log_size === 1 ? "" : "s"}. The similarity score comes from the server and
    is a search hint, not evidence. Each record named below was then checked from this
    browser against the published log: ${verified} of ${states.length} confirmed to be the
    record the server said it was.</p>`;
}

async function render(data) {
  const matches = data.matches ?? [];
  const works = data.works ?? [];
  const actionable = matches.filter((m) => m.band !== Band.WEAK);
  const proofs = await verifyNamed(matches);
  const mine = new Map(works.map((w) => [w.position, w]));

  out.innerHTML = `
  <div class="dash">
    <nav class="side">
      <a href="#" class="on">Possible matches <span class="count${actionable.length ? " alert" : ""}">${actionable.length}</span></a>
      <a href="#">Registered works <span class="count">${works.length}</span></a>
      <a href="#">Dismissed <span class="count">0</span></a>
      <a href="#">Disputes raised <span class="count">0</span></a>
    </nav>
    <div>
      <h1>Possible matches</h1>
      <p class="lede">Work registered by someone else after yours that resembles it. These
        are search results, not findings.</p>

      ${provenance(data, proofs)}

      ${matches.length === 0 && data.searched ? `<p class="muted">Nothing resembling your
        registered work has been registered since. That is the ordinary state.</p>` : ""}

      ${matches.map((m) => {
        const subject = mine.get(m.subject_position);
        const proof = proofs.get(m.candidate_position);
        return `
        <div class="result" style="margin-bottom:16px">
          <div class="rail" style="background:var(--${BAND_RAIL[m.band]})"></div>
          <div class="inner">
            <div class="alert-top">
              <span class="band" style="color:var(--${BAND_RAIL[m.band]})">${BAND_LABEL[m.band]}</span>
              <span class="when">record ${m.candidate_position}</span>
            </div>
            <div class="compare">
              <div class="side-by">
                <span class="eyebrow">Your work</span>
                <div class="t">Record ${m.subject_position}</div>
                <div class="m">${esc(subject?.media_type ?? "unknown")}<br>
                  detail ${quality(subject?.quality)}<br>
                  ${esc((subject?.content_hash ?? "").slice(0, 24))}…</div>
              </div>
              <div class="side-by">
                <span class="eyebrow">Registered later</span>
                <div class="t">Record ${m.candidate_position}</div>
                <div class="m">by ${esc(m.candidate.identity_id)} ·
                  ${esc(m.candidate.assurance_level)}<br>
                  detail ${quality(m.candidate.quality)}<br>
                  ${esc(m.candidate.content_hash.slice(0, 24))}…</div>
              </div>
            </div>
            <div class="dist">
              ${distanceCells(m.distances)}
              <div><span>Lower detail of pair</span>${quality(m.quality)}${
                m.quality == null ? "" :
                `, ${m.quality < LOW_QUALITY_CEILING ? "unreliable" : "reliable"}`}</div>
              <div><span>Checked against the published log</span>${
                esc(proof ? proof.detail : "could not check")}</div>
            </div>
            <p class="caution">${cautionFor(m)}</p>
            <div class="actions">
              ${m.band === Band.STRONG_CANDIDATE
                ? `<button type="button" disabled title="Disputes are not built yet">Open a prior-art claim</button>` : ""}
              <a class="btn-ghost" style="display:inline-block;padding:8px 16px;
                 border:1px solid var(--rule-firm);border-radius:3px;font-size:13px;
                 text-decoration:none;color:var(--ink)"
                 href="./record.html?p=${m.candidate_position}">View their record</a>
            </div>
          </div>
        </div>`;
      }).join("")}

      <table>
        <thead><tr><th>Work</th><th>Position</th><th>Detail</th><th>Similarity</th><th></th></tr></thead>
        <tbody>
          ${works.length === 0 ? `<tr><td colspan="5" class="muted">No work registered yet.
            <a href="./register-work.html">Register one</a>.</td></tr>` : ""}
          ${works.map((w) => `<tr>
            <td>${esc(w.media_type)}<div class="mono muted"
                style="font-size:11.5px">${esc(w.content_hash.slice(0, 20))}…</div></td>
            <td class="mono">${w.position}</td>
            <td class="mono">${quality(w.quality)}</td>
            <td class="mono">${Object.keys(w.similarity_fingerprints ?? {}).join(", ") || "none"}</td>
            <td><a href="./record.html?p=${w.position}">record</a></td>
          </tr>`).join("")}
        </tbody>
      </table>
    </div>
  </div>`;
}
