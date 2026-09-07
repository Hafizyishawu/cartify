// Shared chrome. One definition of the navigation, so seven pages cannot drift
// into disagreeing about what this product offers.

const PAGES = [
  { href: "./index.html", label: "Verify" },
  { href: "./how-it-works.html", label: "How it works" },
  { href: "./for-artists.html", label: "For artists" },
  { href: "./witnesses.html", label: "Witnesses" },
  { href: "./status.html", label: "Status" },
  { href: "./about.html", label: "About" },
];

// Shown only to a signed-in account. The public nav must not advertise a
// destination that turns the visitor away.
const STUDIO_PAGES = [
  { href: "./studio.html", label: "Monitoring" },
  { href: "./register-work.html", label: "Register a work" },
];

export function renderNav(currentHref, signedIn = false) {
  const pages = signedIn ? [...PAGES, ...STUDIO_PAGES] : PAGES;
  const links = pages.map((page) => {
    const on = page.href.endsWith(currentHref) ? ' class="on"' : "";
    return `<a href="${page.href}"${on}>${page.label}</a>`;
  }).join("");

  const account = signedIn
    ? '<a class="signin" href="#" id="sign-out">Sign out</a>'
    : '<a class="signin" href="./sign-in.html">Sign in</a>';

  return `
    <header class="bar">
      <a class="mark" href="./index.html">certi<span>files</span></a>
      <nav>${links}</nav>
      ${account}
    </header>`;
}

export async function mountNav(currentHref) {
  const slot = document.getElementById("nav");
  if (!slot) return null;
  slot.innerHTML = renderNav(currentHref, false);
  let account = { signed_in: false };
  try {
    account = await (await fetch("/api/me", { credentials: "same-origin" })).json();
  } catch {
    // No service behind the static files. The public pages still work, which is
    // the point of them being static.
    return account;
  }
  slot.innerHTML = renderNav(currentHref, account.signed_in);
  const out = document.getElementById("sign-out");
  if (out) {
    out.addEventListener("click", async (event) => {
      event.preventDefault();
      await fetch("/api/sign-out", { method: "POST", credentials: "same-origin" });
      location.href = "./index.html";
    });
  }
  return account;
}

/** Read the published log's manifest, or null when it is unreachable. */
export async function loadManifest(base = "./log") {
  try {
    const response = await fetch(`${base}/manifest.json`, { cache: "no-store" });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  }
}

export function escapeHtml(text) {
  const node = document.createElement("div");
  node.textContent = text ?? "";
  return node.innerHTML;
}
