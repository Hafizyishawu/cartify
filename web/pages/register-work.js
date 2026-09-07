import { mountNav, escapeHtml } from "../site.js";
import { post, me, fingerprintFile } from "../api.js";
mountNav("register-work.html");

let prepared = null;
const el = (id) => document.getElementById(id);
const fail = (message) => el("error").innerHTML = `<div class="err">${message}</div>`;

const account = await me();
if (!account.signed_in) {
  el("gate").innerHTML = `<div class="callout"><p>You need an account to register a work.
    <a href="./sign-in.html">Sign in</a> or <a href="./register.html">create one</a>.
    Checking a file needs neither.</p></div>`;
} else if (!account.may_register_works) {
  // Enforced at the write on the server too. This is the explanation, not the control.
  el("gate").innerHTML = `<div class="callout warn"><p>Your second factor is not active yet.
    Registering a work is asserting authorship, so it needs more than a password.
    <a href="./register.html">Finish setting it up</a>.</p></div>`;
} else {
  el("gate").innerHTML = `<p class="muted" style="font-size:13.5px">Registering as
    <span class="mono">${escapeHtml(account.identity_id)}</span>, assurance
    <span class="mono">${escapeHtml(account.assurance_level)}</span>. That level is recorded
    on the work and cannot be raised afterwards.</p>`;
  el("form").hidden = false;
}

async function choose(file) {
  el("chosen").textContent = `Hashing ${file.name}…`;
  prepared = await fingerprintFile(file);
  el("chosen").innerHTML =
    `<span class="mono">${prepared.sha256.slice(0, 32)}…</span><br>` +
    `${escapeHtml(file.name)}, ${prepared.size_bytes.toLocaleString()} bytes, never uploaded`;
  el("submit").disabled = false;
}

el("drop").addEventListener("click", () => el("file").click());
el("drop").addEventListener("keydown", (e) => {
  if (e.key === "Enter" || e.key === " ") { e.preventDefault(); el("file").click(); }
});
el("file").addEventListener("change", (e) => e.target.files[0] && choose(e.target.files[0]));
for (const type of ["dragenter", "dragover", "dragleave", "drop"]) {
  el("drop").addEventListener(type, (e) => e.preventDefault());
}
el("drop").addEventListener("drop", (e) => e.dataTransfer.files[0] && choose(e.dataTransfer.files[0]));

el("submit").addEventListener("click", async () => {
  el("error").innerHTML = "";
  el("submit").disabled = true;
  try {
    const result = await post("/api/works", {
      ...prepared,
      claim_type: el("claim").value,
      declared_created_at: el("created").value || null,
    });
    el("form").hidden = true;
    el("done").hidden = false;
    el("done").innerHTML = `
      <div class="result">
        <div class="rail" style="background:var(--pending)"></div>
        <div class="inner">
          <div class="state" style="color:var(--pending)">Recorded, awaiting witnesses</div>
          <div class="verdict">Entered in the log at position ${result.position}.</div>
          <p class="muted" style="font-size:13.5px;margin:0">${escapeHtml(result.note)}
            Until then it is real but not yet independently witnessed, and its record page
            will say so.</p>
          <dl class="facts" style="margin-top:12px">
            <div class="fact"><dt>Position</dt><dd>${result.position}</dd></div>
            <div class="fact"><dt>Log size</dt><dd>${result.log_size}</dd></div>
            <div class="fact"><dt>Assurance</dt><dd>${escapeHtml(result.assurance_level)}</dd></div>
          </dl>
          <p style="margin-top:14px"><a href="./record.html?p=${result.position}">View the
            record</a> · <a href="./studio.html">Back to monitoring</a></p>
        </div>
      </div>`;
  } catch (error) {
    fail(error.message);
    el("submit").disabled = false;
  }
});
