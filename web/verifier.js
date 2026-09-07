// Certifiles verifier — RFC 6962 inclusion proofs and checkpoint quorum, in the browser.
//
// The point of this file is that the page does not ask a server whether a record
// is valid. It fetches published data and checks the proof itself, so a
// compromised or lying Certifiles cannot manufacture a positive result. Every
// rule here mirrors certifiles/merkle.py and certifiles/checkpoint.py; the two
// implementations are cross-validated against shared vectors, because two
// verifiers that disagree about what was signed are indistinguishable from a
// forgery.
//
// No DOM access. Runs unchanged under Node for testing.

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;
export const HASH_SIZE = 32;
export const KEY_HASH_SIZE = 4;
export const ED25519_SIGNATURE_SIZE = 64;
// A tree size read from published JSON on a static host is attacker-controlled.
// Beyond this it is not a tree size, and admitting it only offers a way to
// exhaust the verifier rather than be rejected by it.
export const MAX_TREE_SIZE = 2n ** 63n;

export const Status = Object.freeze({
  VALID: "valid",
  VALID_UNDERWITNESSED: "valid_underwitnessed",
  PENDING_WITNESS: "pending_witness",
  NO_RECORD: "no_record",
  UNVERIFIED: "unverified",
  INVALID: "invalid",
  COMPROMISED: "compromised",
});

const encoder = new TextEncoder();

export function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function unhex(text) {
  if (typeof text !== "string" || text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) {
    throw new Error("not lowercase hex");
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function fromBase64(text) {
  const binary = atob(text);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

export function toBase64(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

function concat(...parts) {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

export async function leafHash(data) {
  return sha256(concat(new Uint8Array([LEAF_PREFIX]), data));
}

export async function nodeHash(left, right) {
  return sha256(concat(new Uint8Array([NODE_PREFIX]), left, right));
}

function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

function splitPoint(size) {
  // Largest power of two strictly below size. RFC 6962 splits here rather than
  // at the midpoint, which is what keeps proofs stable as the tree grows.
  if (size < 2n) throw new Error("split point undefined below size 2");
  let k = 1n;
  while (k * 2n < size) k *= 2n;
  return k;
}

function inclusionProofLength(index, size) {
  // Iterative: this runs once per bit of an attacker-supplied size, and
  // recursion would exhaust the stack before any bound could reject it.
  let length = 0;
  let i = index;
  let n = size;
  while (n > 1n) {
    const k = splitPoint(n);
    if (i < k) {
      n = k;
    } else {
      i -= k;
      n -= k;
    }
    length += 1;
  }
  return length;
}

/**
 * Verify a record's inclusion. Returns false rather than throwing: the caller is
 * checking untrusted data, and an exception path is a place to forget a check.
 */
export async function verifyInclusion(leaf, index, treeSize, proof, root) {
  let i;
  let n;
  try {
    i = BigInt(index);
    n = BigInt(treeSize);
  } catch {
    return false;
  }
  if (n < 1n || n > MAX_TREE_SIZE) return false;
  if (i < 0n || i >= n) return false;
  if (!(leaf instanceof Uint8Array) || leaf.length !== HASH_SIZE) return false;
  if (!(root instanceof Uint8Array) || root.length !== HASH_SIZE) return false;
  if (!Array.isArray(proof)) return false;
  if (!proof.every((p) => p instanceof Uint8Array && p.length === HASH_SIZE)) return false;
  if (proof.length !== inclusionProofLength(i, n)) return false;

  let nodeIndex = i;
  let lastIndex = n - 1n;
  let computed = leaf;

  for (const sibling of proof) {
    if (lastIndex === 0n) return false;
    if (nodeIndex % 2n === 1n || nodeIndex === lastIndex) {
      computed = await nodeHash(sibling, computed);
      while (nodeIndex !== 0n && nodeIndex % 2n === 0n) {
        nodeIndex /= 2n;
        lastIndex /= 2n;
      }
    } else {
      computed = await nodeHash(computed, sibling);
    }
    nodeIndex /= 2n;
    lastIndex /= 2n;
  }

  return lastIndex === 0n && equalBytes(computed, root);
}

const SIGNATURE_PREFIX = "— ";

/** Parse a signed checkpoint in the note format. Throws on anything malformed. */
export function parseCheckpoint(bytes) {
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  if (!text.endsWith("\n")) throw new Error("checkpoint must end with a newline");

  const split = text.indexOf("\n\n");
  if (split === -1) throw new Error("missing blank line between body and signatures");
  const bodyText = text.slice(0, split);
  const signatureText = text.slice(split + 2);

  const lines = bodyText.split("\n");
  if (lines.length < 3) throw new Error("body needs origin, size and root");
  const [origin, sizeLine, rootLine, ...extensions] = lines;
  if (sizeLine.length > 20 || !/^(0|[1-9][0-9]*)$/.test(sizeLine)) {
    throw new Error("size must be a canonical decimal integer");
  }
  const rootHash = decodeExact(rootLine, HASH_SIZE, "root hash");

  const signatures = [];
  const signatureLines = signatureText.split("\n");
  if (signatureLines[signatureLines.length - 1] !== "") {
    throw new Error("signature block must end with a newline");
  }
  for (const line of signatureLines.slice(0, -1)) {
    if (!line.startsWith(SIGNATURE_PREFIX)) throw new Error("bad signature line");
    const remainder = line.slice(SIGNATURE_PREFIX.length);
    const gap = remainder.indexOf(" ");
    if (gap === -1) throw new Error("signature line needs a name and a blob");
    const keyName = remainder.slice(0, gap);
    if (!/^[\x21-\x7e]+$/.test(keyName)) throw new Error("bad key name");
    const raw = decodeExact(
      remainder.slice(gap + 1),
      KEY_HASH_SIZE + ED25519_SIGNATURE_SIZE,
      "signature",
    );
    signatures.push({
      keyName,
      keyHash: raw.slice(0, KEY_HASH_SIZE),
      signature: raw.slice(KEY_HASH_SIZE),
    });
  }

  return {
    origin,
    size: BigInt(sizeLine),
    rootHash,
    extensions,
    signatures,
    body: encoder.encode(`${bodyText}\n`),
  };
}

function decodeExact(value, length, what) {
  let raw;
  try {
    raw = fromBase64(value);
  } catch {
    throw new Error(`${what} is not valid base64`);
  }
  if (raw.length !== length) throw new Error(`${what} must decode to ${length} bytes`);
  // Non-canonical base64 would give one checkpoint several wire forms carrying
  // the same quorum under different digests, which defeats comparing bytes to
  // detect a split view.
  if (toBase64(raw) !== value) throw new Error(`${what} is not canonically encoded`);
  return raw;
}

export async function keyHash(keyName, publicKey) {
  return (
    await sha256(concat(encoder.encode(`${keyName}\n`), new Uint8Array([0x01]), publicKey))
  ).slice(0, KEY_HASH_SIZE);
}

export function ed25519Available() {
  return typeof crypto !== "undefined" && !!crypto.subtle;
}

async function verifySignature(publicKey, message, signature) {
  try {
    const key = await crypto.subtle.importKey("raw", publicKey, "Ed25519", false, ["verify"]);
    return await crypto.subtle.verify("Ed25519", key, signature, message);
  } catch {
    // Includes the browser simply not supporting Ed25519. The caller must
    // report that verification could not run, never that it passed.
    return null;
  }
}

/**
 * Count the log signature and the distinct witnesses on a checkpoint.
 *
 * The log's own key is checked separately and never joins the witness count.
 * The operator holds it, and counting it toward K would let one real witness
 * satisfy a quorum of two. Witnesses are deduplicated by public key, not by
 * name, because one key answering to two names is one entity.
 */
export async function verifyQuorum(checkpoint, policy) {
  const logKey = unhex(policy.log_public_key);
  const witnessKeys = new Map(
    Object.entries(policy.witnesses).map(([name, value]) => [name, unhex(value)]),
  );

  let logSigned = false;
  const witnessed = new Map();
  let unsupported = false;

  for (const signature of checkpoint.signatures) {
    const isLog = signature.keyName === policy.log_key_name;
    const key = isLog ? logKey : witnessKeys.get(signature.keyName);
    if (!key) continue;
    if (!equalBytes(signature.keyHash, await keyHash(signature.keyName, key))) continue;

    const result = await verifySignature(key, checkpoint.body, signature.signature);
    if (result === null) {
      unsupported = true;
      continue;
    }
    if (!result) continue;
    if (isLog) logSigned = true;
    else witnessed.set(hex(key), signature.keyName);
  }

  return {
    logSigned,
    witnesses: [...witnessed.values()].sort(),
    required: policy.required,
    meetsQuorum: logSigned && witnessed.size >= policy.required,
    unsupported,
  };
}
