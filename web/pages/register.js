import { mountNav } from "../site.js";
import { post, me } from "../api.js";
mountNav("register.html");

const show = (id) => ["step-account", "step-mfa", "step-done"]
  .forEach((s) => document.getElementById(s).hidden = s !== id);
const fail = (where, message) =>
  document.getElementById(where).innerHTML = `<div class="err">${message}</div>`;

document.getElementById("create").addEventListener("click", async () => {
  document.getElementById("error").innerHTML = "";
  try {
    await post("/api/accounts", {
      email: document.getElementById("email").value.trim(),
      password: document.getElementById("password").value,
    });
    const enrolment = await post("/api/mfa/enrol", {});
    document.getElementById("uri").textContent = enrolment.otpauth_uri;
    show("step-mfa");
  } catch (error) {
    fail("error", error.message);
  }
});

document.getElementById("confirm").addEventListener("click", async () => {
  document.getElementById("mfa-error").innerHTML = "";
  try {
    await post("/api/mfa/confirm", { code: document.getElementById("code").value.trim() });
    const account = await me();
    document.getElementById("identity").textContent = account.identity_id;

    const recovery = await post("/api/recovery/codes", {});
    document.getElementById("codes").textContent = recovery.codes.join("   ");
    // Sent now rather than at account creation: an address confirmed before a
    // second factor exists would raise assurance on an account that cannot yet
    // register anything.
    await post("/api/email/send-verification", {});
    show("step-done");
  } catch (error) {
    fail("mfa-error", error.message);
  }
});
