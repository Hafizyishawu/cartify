import { mountNav } from "../site.js";
import { post } from "../api.js";
mountNav("sign-in.html");

const fail = (where, message) =>
  document.getElementById(where).innerHTML = `<div class="err">${message}</div>`;

document.getElementById("submit").addEventListener("click", async () => {
  document.getElementById("error").innerHTML = "";
  try {
    const result = await post("/api/sign-in", {
      email: document.getElementById("email").value.trim(),
      password: document.getElementById("password").value,
    });
    if (result.next === "enrol-mfa") {
      // An account without a second factor cannot register work, so it is sent
      // to finish setting one up rather than into a studio it cannot use.
      location.href = "./register.html";
      return;
    }
    document.getElementById("step-password").hidden = true;
    document.getElementById("step-code").hidden = false;
    document.getElementById("code").focus();
  } catch (error) {
    fail("error", error.message);
  }
});

document.getElementById("lost").addEventListener("click", (event) => {
  event.preventDefault();
  document.getElementById("step-code").hidden = true;
  document.getElementById("step-recovery").hidden = false;
  document.getElementById("recovery").focus();
});

document.getElementById("use-recovery").addEventListener("click", async () => {
  document.getElementById("recovery-error").innerHTML = "";
  try {
    await post("/api/recovery/use", {
      code: document.getElementById("recovery").value.trim(),
    });
    // The old authenticator secret is gone, deliberately: a code is used when
    // that device is lost, so a fresh factor has to be enrolled before this
    // account can register work again.
    location.href = "./register.html";
  } catch (error) {
    fail("recovery-error", error.message);
  }
});

document.getElementById("verify").addEventListener("click", async () => {
  document.getElementById("code-error").innerHTML = "";
  try {
    await post("/api/mfa/verify", { code: document.getElementById("code").value.trim() });
    location.href = "./studio.html";
  } catch (error) {
    fail("code-error", error.message);
  }
});
