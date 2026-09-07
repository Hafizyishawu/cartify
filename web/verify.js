// The verify flow: fetch published data, check the proof locally, report honestly.
//
// The file never leaves the browser. Only its SHA-256 is used, and every check
// that decides the outcome runs here rather than on a server, because a compromised
// Certifiles must not be able to manufacture a positive result.

import {
  Status,
  hex,
  parseCheckpoint,
  verifyInclusion,
  verifyQuorum,
} from "./verifier.js";

export async function hashFile(file, onProgress) {
  // Streamed in chunks so a large file neither blocks the page nor is held in
  // memory twice. crypto.subtle has no incremental digest, so this uses the
  // whole buffer once but reports progress while reading.
  const buffer = await readWithProgress(file, onProgress);
  const digest = await crypto.subtle.digest("SHA-256", buffer);
  return hex(new Uint8Array(digest));
}

function readWithProgress(file, onProgress) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onprogress = (e) => {
      if (onProgress && e.lengthComputable) onProgress(e.loaded / e.total);
    };
    reader.onload = () => resolve(reader.result);
    reader.onerror = () => reject(new Error("could not read the file"));
    reader.readAsArrayBuffer(file);
  });
}

const shardPosition = (n) => {
  const p = String(n).padStart(12, "0");
  return `${p.slice(0, 4)}/${p.slice(4, 8)}/${p.slice(8)}`;
};
const shardHash = (h) => `${h.slice(0, 2)}/${h.slice(2, 4)}/${h}`;

export function isContentHash(value) {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}

class Site {
  constructor(base) {
    this.base = base.replace(/\/$/, "");
  }

  async json(path) {
    const response = await fetch(`${this.base}/${path}`, { cache: "no-store" });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
    return response.json();
  }

  async bytes(path) {
    const response = await fetch(`${this.base}/${path}`, { cache: "no-store" });
    if (response.status === 404) return null;
    if (!response.ok) throw new Error(`${path}: HTTP ${response.status}`);
    return new Uint8Array(await response.arrayBuffer());
  }
}

/**
 * Look up a fingerprint and verify every claim on it.
 *
 * Returns one result per claim, earliest first. A fingerprint may carry more
 * than one claim. The log records claims and priority is position, so the
 * honest answer is "first registered by X, also claimed by Y" rather than a
 * winner picked here.
 */
export async function verifyFingerprint(baseUrl, contentHash) {
  if (!isContentHash(contentHash)) {
    return { status: Status.INVALID, detail: "That is not a SHA-256 fingerprint." };
  }
  const site = new Site(baseUrl);

  let manifest;
  let checkpointBytes;
  try {
    manifest = await site.json("manifest.json");
    checkpointBytes = await site.bytes("checkpoint");
  } catch (error) {
    return {
      status: Status.UNVERIFIED,
      detail: `The published log could not be reached (${error.message}). This says nothing about the file.`,
    };
  }
  if (!manifest || !checkpointBytes) {
    return {
      status: Status.UNVERIFIED,
      detail: "The published log is missing its manifest or latest checkpoint.",
    };
  }

  let checkpoint;
  try {
    checkpoint = parseCheckpoint(checkpointBytes);
  } catch (error) {
    // A head that will not parse is not a verification failure about the file.
    return { status: Status.UNVERIFIED, detail: `Checkpoint unreadable: ${error.message}` };
  }
  if (hex(checkpoint.rootHash) !== manifest.root_hash ||
      checkpoint.size !== BigInt(manifest.size)) {
    return {
      status: Status.COMPROMISED,
      detail:
        "The published manifest and the signed checkpoint disagree about the log's " +
        "own head. Save both files and publish them: this is evidence, and it " +
        "should not be reported privately to Certifiles.",
      evidence: { manifest, checkpoint: hex(checkpoint.rootHash) },
    };
  }

  const policy = await loadPolicy(site, manifest, checkpoint.size);
  const quorum = policy ? await verifyQuorum(checkpoint, policy) : null;

  const index = await site.json(`index/by-content/${shardHash(contentHash)}.json`);
  if (!index || !index.positions?.length) {
    return {
      status: Status.NO_RECORD,
      detail:
        "Nothing in this log matches that file. Most work is not registered " +
        "anywhere, so this is not evidence that it is copied or fake.",
      manifest,
      quorum,
    };
  }

  const claims = [];
  for (const position of index.positions) {
    claims.push(await verifyClaim(site, position, checkpoint, quorum, contentHash));
  }
  return { status: claims[0].status, claims, manifest, quorum, checkpoint };
}

async function loadPolicy(site, manifest, size) {
  const versions = manifest.policy_versions ?? [];
  let chosen = null;
  for (const version of versions) {
    const policy = await site.json(`policy/${String(version).padStart(6, "0")}.json`);
    if (!policy) continue;
    if (BigInt(policy.effective_from_size) <= size) {
      // Selected by tree size, so a record reports the assurance it actually
      // had rather than one restated by a later policy.
      if (!chosen || policy.effective_from_size >= chosen.effective_from_size) chosen = policy;
    }
  }
  return chosen;
}

async function verifyClaim(site, position, checkpoint, quorum, contentHash) {
  const entry = await site.json(`entries/${shardPosition(position)}.json`);
  const proof = await site.json(`proofs/inclusion/${shardPosition(position)}.json`);
  if (!entry || !proof) {
    return {
      position,
      status: Status.UNVERIFIED,
      detail: "The record or its proof is missing from the published log.",
    };
  }

  const encoder = new TextEncoder();
  const recomputed = await (await import("./verifier.js")).leafHash(encoder.encode(entry.leaf));
  if (hex(recomputed) !== entry.leaf_hash) {
    return {
      position,
      status: Status.INVALID,
      detail: "The published record does not hash to the leaf published beside it.",
    };
  }

  let record;
  try {
    record = JSON.parse(entry.leaf);
  } catch {
    return { position, status: Status.INVALID, detail: "The published record is not valid JSON." };
  }
  if (record.content?.sha256 !== contentHash) {
    return {
      position,
      status: Status.INVALID,
      detail: "The index pointed at a record for a different file.",
    };
  }

  const included = await verifyInclusion(
    recomputed,
    proof.position,
    proof.tree_size,
    proof.proof.map((n) => hexToBytes(n)),
    BigInt(proof.tree_size) === checkpoint.size
      ? checkpoint.rootHash
      : await rootForSize(site, proof.tree_size),
  );

  if (!included) {
    return {
      position,
      status: Status.INVALID,
      detail: "The inclusion proof for this record does not check out against the log.",
    };
  }

  return { position, status: statusFor(quorum), record, proof, detail: detailFor(quorum) };
}

async function rootForSize(site, size) {
  const bytes = await site.bytes(`checkpoints/${String(size).padStart(12, "0")}`);
  if (!bytes) return new Uint8Array(0);
  return parseCheckpoint(bytes).rootHash;
}

function hexToBytes(text) {
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function statusFor(quorum) {
  if (!quorum) return Status.UNVERIFIED;
  if (quorum.unsupported) return Status.UNVERIFIED;
  if (!quorum.logSigned) return Status.INVALID;
  if (quorum.witnesses.length >= quorum.required) return Status.VALID;
  if (quorum.witnesses.length === 0 && quorum.required > 0) return Status.PENDING_WITNESS;
  return Status.VALID_UNDERWITNESSED;
}

function detailFor(quorum) {
  if (!quorum) {
    return "No witness policy is published, so the strength of this record cannot be judged.";
  }
  if (quorum.unsupported) {
    return "This browser cannot check Ed25519 signatures, so the log's signature was not verified. Use the command-line verifier.";
  }
  if (!quorum.logSigned) return "The log's own signature on this checkpoint is not valid.";
  const { witnesses, required } = quorum;
  if (witnesses.length >= required && required > 0) {
    return `Cosigned by ${witnesses.length} independent witness${witnesses.length === 1 ? "" : "es"}: ${witnesses.join(", ")}.`;
  }
  if (required === 0) {
    return "This log runs at stage 0: anchors only, no witnesses recruited yet. Backdating is bounded by the anchor, not by independent parties.";
  }
  if (witnesses.length === 0) {
    return `No witnessed tree head covers this record yet. This policy requires ${required}.`;
  }
  return `${witnesses.length} of ${required} required witness signatures are present.`;
}

/** Load and verify a single record by its log position. */
export async function verifyPosition(baseUrl, position) {
  const site = new Site(baseUrl);
  const manifest = await site.json("manifest.json");
  const checkpointBytes = await site.bytes("checkpoint");
  if (!manifest || !checkpointBytes) {
    return { status: Status.UNVERIFIED, detail: "The published log is unreachable." };
  }
  const checkpoint = parseCheckpoint(checkpointBytes);
  const policy = await loadPolicy(site, manifest, checkpoint.size);
  const quorum = policy ? await verifyQuorum(checkpoint, policy) : null;

  const entry = await site.json(`entries/${shardPosition(position)}.json`);
  if (!entry) {
    return { status: Status.NO_RECORD, detail: `No record at position ${position}.`, manifest };
  }
  const record = JSON.parse(entry.leaf);
  const claim = await verifyClaim(site, position, checkpoint, quorum, record.content.sha256);
  const anchors = await site.json(`anchors/${String(manifest.size).padStart(12, "0")}.json`);
  return { status: claim.status, claim, record, manifest, quorum, checkpoint, policy, anchors };
}

/**
 * Every published record, for a client-side near-match search.
 *
 * Reads the whole log. Verifiable, because the fingerprints are inside records
 * covered by the inclusion proof, so nothing here rests on a server's similarity
 * score. Also linear in log size, and a server-side index has to take over long
 * before the download becomes the problem. The interface says so rather than
 * letting a user discover it.
 */
export async function loadAllEntries(baseUrl, manifest, { verify = false, checkpoint = null } = {}) {
  const site = new Site(baseUrl);
  const { leafHash } = await import("./verifier.js");
  const encoder = new TextEncoder();
  const entries = [];
  for (let position = 0; position < manifest.size; position += 1) {
    const entry = await site.json(`entries/${shardPosition(position)}.json`);
    if (!entry) continue;
    let record;
    try {
      record = JSON.parse(entry.leaf);
    } catch {
      continue;
    }
    let included = null;
    if (verify && checkpoint) {
      const proof = await site.json(`proofs/inclusion/${shardPosition(position)}.json`);
      const recomputed = await leafHash(encoder.encode(entry.leaf));
      included =
        hex(recomputed) === entry.leaf_hash &&
        (await verifyInclusion(
          recomputed, proof.position, proof.tree_size,
          proof.proof.map(hexToBytes),
          BigInt(proof.tree_size) === checkpoint.size ? checkpoint.rootHash : new Uint8Array(0),
        ));
    }
    entries.push({ position, record, content: record.content, included });
  }
  return entries;
}

export { Status };
