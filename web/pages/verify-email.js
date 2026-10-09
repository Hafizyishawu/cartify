import { mountNav, escapeHtml } from "../site.js";
import { post } from "../api.js";
mountNav("verify-email.html");

const out = document.getElementById("out");
const token = new URLSearchParams(location.search).get("token");

if (!token) {
  out.innerHTML = `<div class="err">This link is missing its token. Open the link from your
    email rather than typing the address.</div>`;
} else {
  try {
    const result = await post("/api/email/verify", { token });
    out.innerHTML = `
      <div class="ok">Address confirmed.</div>
      <p class="muted">Work you register from now on is recorded at assurance
        <span class="mono">${escapeHtml(result.assurance_level)}</span>.
        Records you already made keep the level they were issued under, because nothing
        can reach back into the log and change one.</p>
      <p><a href="./register-work.html">Register a work</a> ·
         <a href="./studio.html">Monitoring</a></p>`;
  } catch (error) {
    // A used link and an expired one are the same message on purpose: both mean
    // "ask for a new one", and distinguishing them tells an observer which.
    out.innerHTML = `<div class="err">${escapeHtml(error.message)}</div>
      <p class="muted">Links work once and expire after a day. Sign in and send a new one
      from your account.</p>
      <p><a href="./sign-in.html">Sign in</a></p>`;
  }
}
