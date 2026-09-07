import { loadAllEntries, verifyPosition } from "../verify.js";
import { mountNav } from "../site.js";
mountNav("studio.html");
import { search, BAND_LABEL, BAND_RAIL, BIT_LENGTHS, Band, LOW_QUALITY_CEILING } from "../nearmatch.js";

const params = new URLSearchParams(location.search);
const BASE = params.get("log") || "./log";
const IDENTITY = params.get("identity") || "amara-okonjo-0001";

const esc = (t) => { const d=document.createElement("div"); d.textContent=t??""; return d.innerHTML; };
document.getElementById("who").textContent = IDENTITY;

const manifest = await (await fetch(`${BASE}/manifest.json`, {cache:"no-store"})).json();
const entries = await loadAllEntries(BASE, manifest);
const mine = entries.filter((e) => e.record.issuer.identity_id === IDENTITY);

// Monitoring runs in the direction that matters: work registered *after* mine
// that resembles it. Something registered earlier cannot be a copy of mine.
const alerts = [];
for (const work of mine) {
  for (const candidate of search(work, entries, { afterPosition: work.position })) {
    alerts.push({ work, ...candidate });
  }
}
const ORDER = { strong_candidate: 0, possible: 1, weak: 2 };
alerts.sort((a, b) => ORDER[a.band] - ORDER[b.band]);
const actionable = alerts.filter((a) => a.band !== Band.WEAK);

const distanceCells = (d) => Object.entries(d)
  .map(([k, v]) => `<div><span>${k}</span>${v} / ${BIT_LENGTHS[k]}</div>`).join("");

// The wording has to match the band. Saying "the fingerprints agree" on a weak
// candidate overstates the evidence, which is the failure this whole design is
// built to avoid: a false positive is an accusation handed to the artist.
const cautionFor = (a) => {
  const closeness = "That is similarity, not proof: visual coincidence happens, and the "
    + "measure can be evaded deliberately.";
  if (a.qualityCapped) {
    return `Downgraded despite a close distance. The less detailed of these two images
      scores ${a.quality}/100, below the ${LOW_QUALITY_CEILING} floor, and low-detail
      images collide by coincidence far more often than photographs. Most alerts like
      this one are nothing.`;
  }
  if (a.band === Band.STRONG_CANDIDATE) {
    return `Independent algorithms agree on this, which is what separates a candidate
      from a coincidence. ${closeness} Look at both before you act.`;
  }
  if (a.band === Band.POSSIBLE) {
    return `Close on some measures and not others, so this is worth a look rather than
      a conclusion. ${closeness}`;
  }
  return `Only one measure puts these near each other, and the rest do not. Most alerts
    at this level are nothing; it is here so you can see it, not because it is likely.`;
};

document.getElementById("out").innerHTML = `
  <div class="dash">
    <nav class="side">
      <a href="#" class="on">Possible matches <span class="count${actionable.length?" alert":""}">${actionable.length}</span></a>
      <a href="#">Registered works <span class="count">${mine.length}</span></a>
      <a href="#">Dismissed <span class="count">0</span></a>
      <a href="#">Disputes raised <span class="count">0</span></a>
    </nav>
    <div>
      <h1>Possible matches</h1>
      <p class="lede">Work registered by someone else that resembles yours. These are search
        results, not findings.</p>

      <p class="notice">Searched in this browser over ${manifest.size} published record${manifest.size===1?"":"s"},
        using fingerprints carried inside each record and covered by its inclusion proof, so
        the similarity is computed from verified data rather than taken from a server. This
        reads the whole log, which suits a log this size and will not scale; a server-side
        index has to take over well before the download does.</p>

      ${alerts.length === 0 ? `<p class="muted">Nothing resembling your registered work has been
        registered since. That is the ordinary state.</p>` : ""}

      ${alerts.map((a) => `
        <div class="result" style="margin-bottom:16px">
          <div class="rail" style="background:var(--${BAND_RAIL[a.band]})"></div>
          <div class="inner">
            <div class="alert-top">
              <span class="band" style="color:var(--${BAND_RAIL[a.band]})">${BAND_LABEL[a.band]}</span>
              <span class="when">record ${a.entry.position}</span>
            </div>
            <div class="compare">
              <div class="side-by">
                <span class="eyebrow">Your work</span>
                <div class="t">Record ${a.work.position}</div>
                <div class="m">${esc(a.work.record.content.media_type)}<br>
                  quality ${a.work.record.content.quality ?? "unknown"}/100<br>
                  ${esc(a.work.record.content.sha256.slice(0,24))}…</div>
              </div>
              <div class="side-by">
                <span class="eyebrow">Registered later</span>
                <div class="t">Record ${a.entry.position}</div>
                <div class="m">by ${esc(a.entry.record.issuer.identity_id)} ·
                  ${esc(a.entry.record.issuer.assurance_level)}<br>
                  quality ${a.entry.record.content.quality ?? "unknown"}/100<br>
                  ${esc(a.entry.record.content.sha256.slice(0,24))}…</div>
              </div>
            </div>
            <div class="dist">
              ${distanceCells(a.distances)}
              <div><span>Lower quality of pair</span>${a.quality}/100,
                ${a.quality < LOW_QUALITY_CEILING ? "unreliable" : "reliable"}</div>
            </div>
            <p class="caution">${cautionFor(a)}</p>
            <div class="actions">
              ${a.band === Band.STRONG_CANDIDATE
                ? `<button type="button">Open a prior-art claim</button>` : ""}
              <a class="btn-ghost" style="display:inline-block;padding:8px 16px;
                 border:1px solid var(--rule-firm);border-radius:3px;font-size:13px;
                 text-decoration:none;color:var(--ink)"
                 href="./record.html?p=${a.entry.position}">View their record</a>
              <button class="btn-ghost" type="button">Not a match</button>
            </div>
          </div>
        </div>`).join("")}

      <table>
        <thead><tr><th>Work</th><th>Position</th><th>Assurance</th><th>Fingerprints</th><th></th></tr></thead>
        <tbody>
          ${mine.map((w) => `<tr>
            <td>${esc(w.record.content.media_type)}<div class="mono muted"
                style="font-size:11.5px">${esc(w.record.content.sha256.slice(0,20))}…</div></td>
            <td class="mono">${w.position}</td>
            <td class="mono">${esc(w.record.issuer.assurance_level)}</td>
            <td class="mono">${Object.keys(w.record.content.fingerprints ?? {}).join(", ") || "none"}</td>
            <td><a href="./record.html?p=${w.position}">record</a></td>
          </tr>`).join("")}
        </tbody>
      </table>
    </div>
  </div>`;
