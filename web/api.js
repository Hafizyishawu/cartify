import { similarityFingerprints } from "./similarity.js";

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

/**
 * Everything the server is told about a file. The file itself is never sent.
 *
 * The content hash is what verification and duplicate-claim priority rest on,
 * and anyone holding the file can recompute it. The similarity fingerprints are
 * what monitoring searches over, and nobody can recompute them without the
 * file, so the server takes them on trust. Those are different kinds of claim
 * and the record keeps them apart.
 */
export async function contentHashFile(file) {
  const buffer = await file.arrayBuffer();
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  const sha256 = Array.from(new Uint8Array(digest), (b) =>
    b.toString(16).padStart(2, "0")).join("");
  const prepared = {
    sha256,
    size_bytes: file.size,
    media_type: file.type || "application/octet-stream",
  };

  // Only images have similarity fingerprints, and most files registered here
  // will not be images. A failure to derive them is not a failure to register:
  // the authorship claim rests on the content hash alone.
  try {
    const similarity = await similarityFingerprints(file);
    if (similarity) {
      prepared.similarity_fingerprints = similarity.fingerprints;
      prepared.derivation_version = similarity.derivation_version;
    }
  } catch {
    // Left absent rather than guessed. An absent fingerprint means monitoring
    // cannot search this work, which is visible on the record and honest.
  }
  return prepared;
}
