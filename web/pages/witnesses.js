import { mountNav, loadManifest, escapeHtml } from "../site.js";
import { parseCheckpoint, verifyQuorum } from "../verifier.js";

mountNav("witnesses.html");
const BASE = new URLSearchParams(location.search).get("log") || "./log";
const out = document.getElementById("out");

const STAGES = [
  { k: 0, n: 0, name: "Stage 0", gate: "Anchors only. Free tier." },
  { k: 1, n: 2, name: "Stage 1", gate: "First external cosigner in production." },
  { k: 2, n: 4, name: "Stage 2", gate: "Required before any paid tier is sold." },
  { k: 3, n: 7, name: "Stage 3", gate: "Target steady state." },
];

const manifest = await loadManifest(BASE);
if (!manifest) {
  out.innerHTML = `<div class="callout warn"><p>The published policy is unreachable.</p></div>`;
} else {
  const versions = manifest.policy_versions ?? [];
  const policies = [];
  for (const version of versions) {
    const response = await fetch(`${BASE}/policy/${String(version).padStart(6, "0")}.json`);
    if (response.ok) policies.push(await response.json());
  }
  const current = policies.length
    ? policies.reduce((a, b) => (b.effective_from_size >= a.effective_from_size ? b : a))
    : null;

  let signed = [];
  try {
    const bytes = new Uint8Array(
      await (await fetch(`${BASE}/checkpoint`, { cache: "no-store" })).arrayBuffer(),
    );
    const checkpoint = parseCheckpoint(bytes);
    if (current) signed = (await verifyQuorum(checkpoint, current)).witnesses;
  } catch { /* the status page reports checkpoint faults; this page shows the roster */ }

  const stage = current
    ? STAGES.slice().reverse().find((s) => current.required >= s.k) ?? STAGES[0]
    : STAGES[0];

  out.innerHTML = `
    <dl class="stat">
      <div class="cell"><dt>Required</dt><dd>${current ? current.required : "none"}
        <small>distinct witnesses per tree head</small></dd></div>
      <div class="cell"><dt>In the policy</dt><dd>${current ? Object.keys(current.witnesses).length : 0}
        <small>policy v${current ? current.version : "?"}</small></dd></div>
      <div class="cell"><dt>Signed the latest head</dt><dd>${signed.length}
        <small>verified in your browser</small></dd></div>
      <div class="cell"><dt>Stage</dt><dd>${stage.name}<small>${escapeHtml(stage.gate)}</small></dd></div>
    </dl>

    ${current && current.required === 0 ? `<div class="callout warn"><p><strong>No witnesses
      have been recruited.</strong> This log runs on anchors alone. That bounds how far back a
      record can be dated and does nothing to stop us serving two histories. We say so here
      rather than letting you assume otherwise, and the paid tier stays closed until two
      independent organisations cosign.</p></div>` : ""}

    ${current && Object.keys(current.witnesses).length ? `
      <table>
        <thead><tr><th>Witness</th><th>Public key</th><th>Signed latest head</th></tr></thead>
        <tbody>${Object.entries(current.witnesses).map(([name, key]) => `
          <tr><td>${escapeHtml(name)}</td>
              <td class="mono">${escapeHtml(key.slice(0, 24))}…</td>
              <td class="mono" style="color:var(--${signed.includes(name) ? "proven" : "pending"})">
                ${signed.includes(name) ? "yes" : "not yet"}</td></tr>`).join("")}
        </tbody>
      </table>` : ""}

    <h2 style="font-size:19px;font-weight:600;margin:36px 0 8px">Quorum by stage</h2>
    <table>
      <thead><tr><th>Stage</th><th>Required</th><th>In policy</th><th>Gate</th></tr></thead>
      <tbody>${STAGES.map((s) => `
        <tr style="${s.k === (current?.required ?? 0) ? "background:var(--surface-2)" : ""}">
          <td>${s.name}</td><td class="mono">K=${s.k}</td><td class="mono">${s.n}</td>
          <td>${escapeHtml(s.gate)}</td></tr>`).join("")}
      </tbody>
    </table>
    <p class="muted" style="font-size:13px;margin-top:10px">Two is the point at which forging
      history needs a conspiracy rather than a single compromise.</p>`;
}
