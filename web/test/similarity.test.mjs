// Tests for the browser similarity fingerprinter, run in node against the pure
// half of the pipeline. Decoding needs a browser; everything after it does not,
// and everything after it is where the properties live.
//
// The load-bearing test is resize invariance. A fingerprint that does not
// survive a rescale detects nothing, because a copy is almost never the same
// dimensions as the original.

import {
  DERIVATION_VERSION, boxDownscale, dctBlock, dhashFrom, phashFrom, toGrayscale,
} from "../similarity.js";

let failures = 0;
let checks = 0;

function check(name, condition, detail = "") {
  checks += 1;
  if (!condition) {
    failures += 1;
    console.log(`  FAIL  ${name}${detail ? `: ${detail}` : ""}`);
  }
}

const hamming = (a, b) => {
  let d = 0;
  for (let i = 0; i < a.length; i += 1) {
    d += ((parseInt(a[i], 16) ^ parseInt(b[i], 16)).toString(2).match(/1/g) || []).length;
  }
  return d;
};

/** A deterministic pseudo-image with real low-frequency structure. */
function scene(width, height, seed = 1) {
  const gray = new Float64Array(width * height);
  let state = seed;
  const rand = () => (state = (state * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  const blobs = Array.from({ length: 6 }, () => ({
    x: rand(), y: rand(), r: 0.1 + rand() * 0.3, v: rand() * 255,
  }));
  for (let y = 0; y < height; y += 1) {
    for (let x = 0; x < width; x += 1) {
      const nx = x / width;
      const ny = y / height;
      let value = 40 + 60 * Math.sin(nx * 5) * Math.cos(ny * 4);
      for (const b of blobs) {
        const d = Math.hypot(nx - b.x, ny - b.y);
        if (d < b.r) value += b.v * (1 - d / b.r);
      }
      gray[y * width + x] = Math.max(0, Math.min(255, value));
    }
  }
  return gray;
}

const flat = (w, h, v = 200) => Float64Array.from({ length: w * h }, () => v);
const gradient = (w, h) =>
  Float64Array.from({ length: w * h }, (_, i) => ((i % w) / w) * 255);

const fingerprint = (gray, w, h) => ({
  phash: phashFrom(gray, w, h).hex,
  dhash: dhashFrom(gray, w, h),
});

console.log(`similarity fingerprinter, derivation version ${DERIVATION_VERSION}`);

// ---- shape -----------------------------------------------------------------
{
  const f = fingerprint(scene(256, 256), 256, 256);
  check("phash is 16 lowercase hex characters", /^[0-9a-f]{16}$/.test(f.phash), f.phash);
  check("dhash is 16 lowercase hex characters", /^[0-9a-f]{16}$/.test(f.dhash), f.dhash);
  // The DC slot is filled with a constant, so the top bit is always clear and
  // the first nibble can never exceed 7. That keeps the width the schema wants
  // while contributing nothing to any distance.
  check("the DC slot is a constant, not a value",
        parseInt(f.phash[0], 16) < 8, f.phash);
}

// ---- determinism -----------------------------------------------------------
{
  const a = fingerprint(scene(300, 200, 7), 300, 200);
  const b = fingerprint(scene(300, 200, 7), 300, 200);
  check("the same pixels give the same fingerprint",
        a.phash === b.phash && a.dhash === b.dhash);
}

// ---- resize invariance, the property the feature depends on ----------------
for (const [w, h] of [[512, 512], [200, 200], [640, 480], [97, 131]]) {
  const original = scene(400, 400, 3);
  const full = fingerprint(original, 400, 400);
  const resized = boxDownscale(original, 400, 400, w, h);
  const after = fingerprint(resized, w, h);
  check(`phash survives a resize to ${w}x${h}`, hamming(full.phash, after.phash) <= 8,
        `distance ${hamming(full.phash, after.phash)}/64`);
  check(`dhash survives a resize to ${w}x${h}`, hamming(full.dhash, after.dhash) <= 12,
        `distance ${hamming(full.dhash, after.dhash)}/64`);
}

// ---- unrelated images are far apart ----------------------------------------
{
  const a = fingerprint(scene(300, 300, 11), 300, 300);
  const b = fingerprint(scene(300, 300, 99), 300, 300);
  check("unrelated scenes are far apart in phash", hamming(a.phash, b.phash) >= 16,
        `distance ${hamming(a.phash, b.phash)}/64`);
  check("unrelated scenes are far apart in dhash", hamming(a.dhash, b.dhash) >= 16,
        `distance ${hamming(a.dhash, b.dhash)}/64`);
}

// ---- brightness is deliberately ignored by phash ---------------------------
{
  const base = scene(256, 256, 5);
  const brighter = base.map((v) => Math.min(255, v * 1.25));
  check("phash ignores a uniform brightness change",
        hamming(fingerprint(base, 256, 256).phash,
                fingerprint(brighter, 256, 256).phash) <= 6,
        `distance ${hamming(fingerprint(base, 256, 256).phash, fingerprint(brighter, 256, 256).phash)}/64`);
}

// Quality is not computed in derivation version 1. The cases below are kept as
// a record of why: none of the candidate formulations separated them in the
// right direction, which is what the eval corpus has to settle.
{
  const flatP = fingerprint(flat(256, 256), 256, 256);
  const gradP = fingerprint(gradient(256, 256), 256, 256);
  check("a flat fill still produces a well-formed phash",
        /^[0-9a-f]{16}$/.test(flatP.phash), flatP.phash);
  check("a flat fill and a gradient do not collide",
        hamming(flatP.phash, gradP.phash) > 0);
}

// ---- the downscaler ---------------------------------------------------------
{
  // Four source pixels averaging into one target pixel.
  const out = boxDownscale(Float64Array.from([0, 100, 200, 60]), 2, 2, 1, 1);
  check("a 2x2 to 1x1 downscale is the mean", Math.abs(out[0] - 90) < 1e-9, `${out[0]}`);

  // Non-integer ratio: 3 wide into 2, so the middle column is split.
  const uneven = boxDownscale(Float64Array.from([0, 90, 180]), 3, 1, 2, 1);
  check("a non-integer ratio weights by overlap",
        Math.abs(uneven[0] - 30) < 1e-9 && Math.abs(uneven[1] - 150) < 1e-9,
        `${uneven[0]}, ${uneven[1]}`);

  // Upscaling must not produce black cells where no source pixel lands.
  const up = boxDownscale(Float64Array.from([50, 150]), 2, 1, 4, 1);
  check("upscaling never yields an empty cell", Array.from(up).every((v) => v > 0),
        Array.from(up).join(","));
}

// ---- the DCT ----------------------------------------------------------------
{
  // A constant input puts all energy in the DC term and none anywhere else.
  const block = dctBlock(flat(8, 8, 100), 8, 4);
  check("a constant image has only a DC coefficient",
        Math.abs(block[0] - 800) < 1e-6
        && Array.from(block).slice(1).every((v) => Math.abs(v) < 1e-9),
        `dc ${block[0]}`);

  // Against a direct, unoptimised DCT-II, to catch an error in the separable form.
  const size = 8;
  const values = scene(size, size, 4);
  const fast = dctBlock(values, size, 4);
  const alpha = (k) => (k === 0 ? Math.sqrt(1 / size) : Math.sqrt(2 / size));
  let worst = 0;
  for (let v = 0; v < 4; v += 1) {
    for (let u = 0; u < 4; u += 1) {
      let sum = 0;
      for (let y = 0; y < size; y += 1) {
        for (let x = 0; x < size; x += 1) {
          sum += values[y * size + x]
            * Math.cos(((2 * x + 1) * u * Math.PI) / (2 * size))
            * Math.cos(((2 * y + 1) * v * Math.PI) / (2 * size));
        }
      }
      worst = Math.max(worst, Math.abs(alpha(u) * alpha(v) * sum - fast[v * 4 + u]));
    }
  }
  check("the separable DCT matches a direct one", worst < 1e-9, `worst error ${worst}`);
}

// ---- grayscale --------------------------------------------------------------
{
  const rgba = { width: 2, height: 1, data: Uint8ClampedArray.from([
    255, 255, 255, 255,   // opaque white
    0, 0, 0, 0,           // fully transparent, must composite to white
  ]) };
  const gray = toGrayscale(rgba);
  check("opaque white is 255", Math.abs(gray[0] - 255) < 1e-9, `${gray[0]}`);
  check("transparent composites over white, not black",
        Math.abs(gray[1] - 255) < 1e-9, `${gray[1]}`);
}

console.log(`\n  ${checks - failures}/${checks} checks passed`);
if (failures) process.exit(1);
