import { mountNav, escapeHtml } from "../site.js";
import { post, me } from "../api.js";
mountNav("settings.html");

const el = (id) => document.getElementById(id);
const fail = (message) => el("error").innerHTML = `<div class="err">${message}</div>`;

// The ladder is the explanation, not the control: every rung is enforced at the
// point work is registered. Showing it here is what makes the levels on a
// record mean something to the person who has to earn them.
const RUNGS = [
  {
    level: "unverified",
    title: "Account only",
    held: "An account exists and controls this password.",
    todo: "An account exists and controls this password.",
  },
  {
    level: "email",
    title: "Email confirmed",
    held: "Someone reads this inbox. It is a way to reach you, not a way to name you.",
    todo: "Confirm your address to show that this account can be reached. "
        + "Check your inbox, or start again from the account you created.",
  },
  {
    level: "domain",
    title: "Domain proved",
    held: "You published a record on a name you control, and two resolvers agreed on it.",
    todo: "Publish a TXT record on a domain you control. This is the level a buyer or a "
        + "gallery can actually recognise.",
  },
];

function renderLadder(current) {
  const reached = RUNGS.findIndex((rung) => rung.level === current);
  el("ladder").innerHTML = RUNGS.map((rung, index) => {
    const held = index <= reached;
    const now = index === reached + 1;
    const tag = held ? "held" : now ? "next" : "later";
    return `
      <div class="rung${held ? " held" : now ? " now" : ""}">
        <div class="pip"></div>
        <div>
          <h3>${escapeHtml(rung.title)} <span class="tag">${tag}</span></h3>
          <p>${escapeHtml(held ? rung.held : rung.todo)}</p>
        </div>
      </div>`;
  }).join("");
}

const account = await me();
// The ladder is climbed in order, and the server enforces it. A domain proof is
// the stronger claim, but it does not make the account reachable, and alerts and
// recovery both need an address that answers.
let emailConfirmed = account.assurance_level !== "unverified";

if (!account.signed_in) {
  el("gate").innerHTML = `<div class="callout"><p>Settings belong to an account.
    <a href="./sign-in.html">Sign in</a> to see yours.</p></div>`;
} else {
  el("account").hidden = false;
  renderLadder(account.assurance_level);
  renderEmailGate();
}

function renderEmailGate() {
  const slot = el("email-gate");
  if (emailConfirmed) {
    slot.innerHTML = "";
    return;
  }
  // Not hidden behind the gate: publishing DNS is the slow half, so getting the
  // record out while the confirmation email is still in flight is time saved.
  slot.innerHTML = `
    <div class="callout warn">
      <p><strong>Confirm your email address before checking.</strong> You can take the
      record below and publish it now; DNS is the slow part. The check itself needs a
      confirmed address, because that is where alerts about your work and every recovery
      path go.</p>
      <p style="margin-top:8px"><button type="button" id="resend" class="btn-ghost"
        style="width:auto;padding:6px 12px;font-size:12px">Send the confirmation email
        again</button> <span id="resent" class="muted"></span></p>
    </div>`;
  el("resend").addEventListener("click", async () => {
    const button = el("resend");
    button.disabled = true;
    try {
      await post("/api/email/send-verification", {});
      el("resent").textContent = `Sent to ${account.email}.`;
    } catch (error) {
      el("resent").textContent = error.message;
      button.disabled = false;
    }
  });
}

el("get-record").addEventListener("click", async () => {
  el("error").innerHTML = "";
  el("challenge").hidden = true;
  const button = el("get-record");
  button.disabled = true;
  try {
    const challenge = await post("/api/domain/challenge", { domain: el("domain").value });
    showChallenge(challenge);
  } catch (error) {
    fail(escapeHtml(error.message));
  } finally {
    button.disabled = false;
  }
});

function showChallenge(challenge) {
  const slot = el("challenge");
  slot.hidden = false;
  slot.innerHTML = `
    <div class="result" style="margin-top:24px">
      <div class="rail" style="background:var(--pending)"></div>
      <div class="inner">
        <div class="state" style="color:var(--pending)">Awaiting the record</div>
        <div class="verdict">Publish this on
          <span class="mono">${escapeHtml(challenge.domain)}</span></div>

        <p class="muted" style="font-size:13.5px;margin:0 0 14px">The value is derived from
          your account and this domain together, under a key held by the server. Nobody can
          work out what record another account would need, which is what stops someone
          claiming a domain the moment its real owner publishes their own.</p>

        <div class="rows" style="margin-bottom:16px">
          <div class="row"><dt>Type</dt><dd class="mono">TXT</dd></div>
          <div class="row"><dt>Name</dt><dd class="mono">${escapeHtml(challenge.record_name)}</dd></div>
        </div>

        <div class="copyable">
          <div class="secret" id="record-value">${escapeHtml(challenge.record_value)}</div>
          <button type="button" id="copy" class="btn-ghost">Copy</button>
        </div>

        <p class="muted" style="font-size:12.5px;margin:0 0 16px">Some DNS panels append the
          domain to the name for you. If yours does, enter
          <span class="mono">_certifiles</span> alone rather than the full name above.</p>

        <button type="button" id="check" style="width:auto"
          ${emailConfirmed ? "" : "disabled"}>Check now</button>
        ${emailConfirmed ? "" : `<p class="muted" style="font-size:12.5px;margin:10px 0 0">
          Available once your email address is confirmed. Publish the record meanwhile.</p>`}
        <div id="outcome" style="margin-top:16px"></div>
      </div>
    </div>`;

  el("copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(challenge.record_value);
      el("copy").textContent = "Copied";
    } catch {
      // Clipboard access can be refused, and the value is on screen regardless.
      el("copy").textContent = "Select it above";
    }
  });

  el("check").addEventListener("click", () => check(challenge));
}

async function check(challenge) {
  const button = el("check");
  button.disabled = true;
  button.textContent = "Checking…";
  el("outcome").innerHTML = "";
  try {
    await post("/api/domain/verify", { domain: challenge.domain });
    proved(challenge.domain);
  } catch (error) {
    // Three outcomes, and conflating any two of them would be a lie. 400 means
    // the resolvers answered and the record was not there. 503 means no answer
    // arrived, which says nothing at all about who owns the domain.
    if (error.status === 403) {
      // The state changed under us: confirmed in another tab, or never was.
      emailConfirmed = false;
      renderEmailGate();
      el("outcome").innerHTML = `<div class="err">${escapeHtml(error.message)}</div>`;
    } else if (error.status === 503) {
      el("outcome").innerHTML = `<div class="err">
        <strong>Not checked.</strong> ${escapeHtml(error.message)} Your domain has not been
        judged either way. Try again shortly.</div>`;
    } else if (error.status === 429) {
      el("outcome").innerHTML = `<div class="err">Too many checks. Wait a moment.</div>`;
    } else {
      el("outcome").innerHTML = `<div class="err">
        <strong>Not found yet.</strong> ${escapeHtml(error.message)} Either the record is
        not published, or it has not reached both resolvers yet. Records commonly take
        minutes and occasionally hours.</div>`;
    }
  } finally {
    button.disabled = false;
    button.textContent = "Check again";
  }
}

function proved(domain) {
  el("challenge").innerHTML = `
    <div class="result" style="margin-top:24px">
      <div class="rail" style="background:var(--proven)"></div>
      <div class="inner">
        <div class="state" style="color:var(--proven)">Domain proved</div>
        <div class="verdict"><span class="mono">${escapeHtml(domain)}</span> is yours</div>
        <p class="muted" style="font-size:13.5px;margin:0 0 12px">Work you register from now
          on carries the domain assurance level. Records already in the log keep the level
          they were issued under, permanently.</p>
        <p class="muted" style="font-size:12.5px;margin:0 0 14px">Leave the TXT record in
          place. Domains change hands, so the proof is rechecked rather than remembered, and
          removing the record will eventually withdraw the claim.</p>
        <a href="./register-work.html">Register a work</a>
      </div>
    </div>`;
  renderLadder("domain");
  emailConfirmed = true;
  renderEmailGate();
}
