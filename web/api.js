// Talking to the service. One place that knows about the CSRF header and what
// an error response looks like, so no page reimplements either.

let csrfToken = null;

export async function me() {
  const response = await fetch("/api/me", { credentials: "same-origin" });
  const body = await response.json();
  csrfToken = body.csrf_token ?? null;
  return body;
}

export async function post(path, body) {
  const headers = { "Content-Type": "application/json" };
  // Refreshed lazily: a session that has just rotated its token, which happens
  // on every second-factor step, carries a different CSRF token.
  if (csrfToken === null) await me();
  if (csrfToken) headers["X-CSRF-Token"] = csrfToken;

  const response = await fetch(path, {
    method: "POST",
    credentials: "same-origin",
    headers,
    body: JSON.stringify(body ?? {}),
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(payload.error || `Request failed (${response.status}).`);
    error.status = response.status;
    error.retryAfter = Number(response.headers.get("Retry-After") || 0);
    throw error;
  }
  // Any successful state change may have rotated the session.
  csrfToken = null;
  return payload;
}

/** Fingerprint a file in the browser. The file itself is never sent. */
export async function fingerprintFile(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const sha256 = Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0")).join("");
  return { sha256, size_bytes: file.size, media_type: file.type || "application/octet-stream" };
}
