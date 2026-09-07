import { mountNav, escapeHtml } from "../site.js";
import { post } from "../api.js";
mountNav("reset-password.html");

const el = (id) => document.getElementById(id);
const token = new URLSearchParams(location.search).get("token");

if (!token) {
  el("bad").hidden = false;
  el("bad").innerHTML = `<div class="err">This link is missing its token.</div>
    <p class="muted">Open the link from your email rather than typing the address.</p>
    <p><a href="./forgot-password.html">Ask for a new link</a></p>`;
} else {
  el("form").hidden = false;
}

el("submit").addEventListener("click", async () => {
  const password = el("password").value;
  const confirm = el("confirm").value;
  el("error").innerHTML = "";

  if (password !== confirm) {
    // Checked here rather than server-side: the two fields exist to catch a
    // typo, and sending a mistyped password would consume the single-use token.
    el("error").innerHTML = `<div class="err">Those two do not match.</div>`;
    return;
  }

  el("submit").disabled = true;
  try {
    await post("/api/password/reset", { token, password });
    el("form").hidden = true;
    el("done").hidden = false;
  } catch (error) {
    el("error").innerHTML = `<div class="err">${escapeHtml(error.message)}</div>`;
    // A rejected password does not spend the link, so retrying here works. Only
    // a link that is genuinely used or expired needs a new one.
    if (error.message.includes("link")) {
      el("error").innerHTML +=
        `<p class="muted"><a href="./forgot-password.html">Ask for a new link</a></p>`;
    } else {
      el("submit").disabled = false;
    }
  }
});
