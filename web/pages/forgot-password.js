import { mountNav, escapeHtml } from "../site.js";
import { post } from "../api.js";
mountNav("forgot-password.html");

document.getElementById("submit").addEventListener("click", async () => {
  const button = document.getElementById("submit");
  button.disabled = true;
  document.getElementById("error").innerHTML = "";
  try {
    await post("/api/password/forgot", {
      email: document.getElementById("email").value.trim(),
    });
    // Shown whatever the outcome. The service answers identically for a
    // registered and an unregistered address, and this page must not undo that.
    document.getElementById("form").hidden = true;
    document.getElementById("sent").hidden = false;
  } catch (error) {
    document.getElementById("error").innerHTML =
      `<div class="err">${escapeHtml(error.message)}</div>`;
    button.disabled = false;
  }
});
