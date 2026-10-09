// Computing similarity fingerprints in the browser, from pixels the server
// never sees.
//
// Two rules shape every line below.
//
// **The pipeline is owned, not delegated.** Canvas `drawImage` scaling is
// implementation defined: Chrome, Firefox and Safari produce different pixels
// for the same downscale, and one browser differs between its GPU and CPU
// paths. Canvas is used here only to decode an image at its natural size.
// Every resampling step is implemented below so the derivation is specified
// rather than inherited.
//
// **The derivation is versioned.** A record states which version produced its
// fingerprints, because a value computed under one pipeline is not comparable
// with one computed under another, and the file is never stored so nothing can
// be recomputed retroactively. Changing any constant here means a new version.
//
// The remaining source of variance is image decoding itself. PNG is lossless
// and exact; JPEG decoders differ in IDCT precision, so the same JPEG can yield
// pixel values that differ by a unit or two between browsers. That moves a
// perceptual hash by a bit or two and is why comparisons are banded rather than
// exact.

export const DERIVATION_VERSION = 1;

// ITU-R BT.601 luma coefficients. Fixed here rather than taken from a canvas
// colour-space conversion, which is not specified across browsers.
const LUMA_R = 0.299;
const LUMA_G = 0.587;
const LUMA_B = 0.114;

const PHASH_GRID = 32;   // DCT input, downscaled from the full image
const PHASH_BLOCK = 8;   // top-left DCT coefficients that become the hash
const DHASH_WIDTH = 9;   // one wider than tall: 8 horizontal comparisons a row
const DHASH_HEIGHT = 8;

export class FingerprintError extends Error {}

/** Decode to full-size RGBA. The only step canvas is trusted with. */
async function decode(file) {
  let bitmap;
  try {
    bitmap = await createImageBitmap(file);
  } catch (cause) {
    throw new FingerprintError("that file could not be decoded as an image");
  }
  const { width, height } = bitmap;
  if (!width || !height) throw new FingerprintError("the image has no pixels");

  const canvas = new OffscreenCanvas(width, height);
  const context = canvas.getContext("2d", { willReadFrequently: true });
  context.drawImage(bitmap, 0, 0);
  bitmap.close();
  return context.getImageData(0, 0, width, height);
}

/** RGBA to a single grayscale plane, alpha composited over white. */
export function toGrayscale({ data, width, height }) {
  const gray = new Float64Array(width * height);
  for (let i = 0, p = 0; p < gray.length; i += 4, p += 1) {
    // Compositing over white rather than ignoring alpha: a transparent PNG
    // otherwise hashes as though its background were black, and the same
    // artwork exported as JPEG on white would not resemble it at all.
    const a = data[i + 3] / 255;
    const r = data[i] * a + 255 * (1 - a);
    const g = data[i + 1] * a + 255 * (1 - a);
    const b = data[i + 2] * a + 255 * (1 - a);
    gray[p] = LUMA_R * r + LUMA_G * g + LUMA_B * b;
  }
  return gray;
}

/**
 * Area-average downscale to an exact target size.
 *
 * Every source pixel contributes to exactly one target cell, weighted by the
 * area of overlap, so the result does not depend on the source dimensions being
 * a multiple of the target. Written out rather than delegated because this is
 * the step browsers disagree about.
 */
export function boxDownscale(gray, width, height, targetWidth, targetHeight) {
  if (targetWidth <= 0 || targetHeight <= 0) {
    throw new FingerprintError("target dimensions must be positive");
  }
  const out = new Float64Array(targetWidth * targetHeight);
  const scaleX = width / targetWidth;
  const scaleY = height / targetHeight;

  for (let ty = 0; ty < targetHeight; ty += 1) {
    const y0 = ty * scaleY;
    const y1 = (ty + 1) * scaleY;
    for (let tx = 0; tx < targetWidth; tx += 1) {
      const x0 = tx * scaleX;
      const x1 = (tx + 1) * scaleX;

      let total = 0;
      let weight = 0;
      for (let sy = Math.floor(y0); sy < Math.min(Math.ceil(y1), height); sy += 1) {
        const wy = Math.min(sy + 1, y1) - Math.max(sy, y0);
        if (wy <= 0) continue;
        for (let sx = Math.floor(x0); sx < Math.min(Math.ceil(x1), width); sx += 1) {
          const wx = Math.min(sx + 1, x1) - Math.max(sx, x0);
          if (wx <= 0) continue;
          total += gray[sy * width + sx] * wy * wx;
          weight += wy * wx;
        }
      }
      // A target cell can only be empty if the source is smaller than the
      // target in that axis, in which case the nearest source pixel is the
      // honest answer rather than zero, which would read as pure black.
      out[ty * targetWidth + tx] = weight > 0
        ? total / weight
        : gray[Math.min(height - 1, Math.floor(y0)) * width
               + Math.min(width - 1, Math.floor(x0))];
    }
  }
  return out;
}

/**
 * Separable 2D DCT-II, returning only the top-left `block` coefficients.
 *
 * The full 32x32 transform is never needed: pHash keeps an 8x8 corner, so rows
 * are transformed in full and only the low-frequency columns are kept.
 */
export function dctBlock(values, size, block) {
  const cos = new Float64Array(size * size);
  for (let k = 0; k < size; k += 1) {
    for (let n = 0; n < size; n += 1) {
      cos[k * size + n] = Math.cos(((2 * n + 1) * k * Math.PI) / (2 * size));
    }
  }
  const alpha = (k) => (k === 0 ? Math.sqrt(1 / size) : Math.sqrt(2 / size));

  const rows = new Float64Array(size * block);
  for (let y = 0; y < size; y += 1) {
    for (let u = 0; u < block; u += 1) {
      let sum = 0;
      for (let x = 0; x < size; x += 1) sum += values[y * size + x] * cos[u * size + x];
      rows[y * block + u] = alpha(u) * sum;
    }
  }

  const out = new Float64Array(block * block);
  for (let u = 0; u < block; u += 1) {
    for (let v = 0; v < block; v += 1) {
      let sum = 0;
      for (let y = 0; y < size; y += 1) sum += rows[y * block + u] * cos[v * size + y];
      out[v * block + u] = alpha(v) * sum;
    }
  }
  return out;
}

function bitsToHex(bits) {
  let hex = "";
  for (let byte = 0; byte < bits.length / 4; byte += 1) {
    let nibble = 0;
    for (let i = 0; i < 4; i += 1) nibble = (nibble << 1) | bits[byte * 4 + i];
    hex += nibble.toString(16);
  }
  return hex;
}

function median(values) {
  const sorted = Array.from(values).sort((a, b) => a - b);
  const mid = sorted.length >> 1;
  return sorted.length % 2 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

/**
 * pHash: low-frequency structure, thresholded at its own median.
 *
 * The DC coefficient is excluded from the median and from the hash. It carries
 * overall brightness, so including it would make the same image at two
 * exposures hash differently, which is the opposite of what this is for.
 */
export function phashFrom(gray, width, height) {
  const small = boxDownscale(gray, width, height, PHASH_GRID, PHASH_GRID);
  const block = dctBlock(small, PHASH_GRID, PHASH_BLOCK);
  const ac = Array.from(block).slice(1);
  const threshold = median(ac);
  const bits = ac.map((value) => (value > threshold ? 1 : 0));
  // 63 AC coefficients, and the hash is 64 bits wide. The DC slot is filled
  // with a constant rather than a value, so it contributes nothing to any
  // distance while keeping the width the record schema expects.
  return { hex: bitsToHex([0, ...bits]), ac };
}

/** dHash: whether each pixel is brighter than the one to its right. */
export function dhashFrom(gray, width, height) {
  const small = boxDownscale(gray, width, height, DHASH_WIDTH, DHASH_HEIGHT);
  const bits = [];
  for (let y = 0; y < DHASH_HEIGHT; y += 1) {
    for (let x = 0; x < DHASH_WIDTH - 1; x += 1) {
      const left = small[y * DHASH_WIDTH + x];
      const right = small[y * DHASH_WIDTH + x + 1];
      bits.push(left > right ? 1 : 0);
    }
  }
  return bitsToHex(bits);
}

// Quality is deliberately absent from derivation version 1.
//
// Unlike TIGHT and LOOSE, which are applied at comparison time and can be
// retuned whenever a better number arrives, quality is written into the record
// and the file is never stored, so a guess made today can never be corrected.
// Candidate formulations were tried against synthetic images and none separated
// a smooth gradient from a photograph in the right direction, which is an
// empirical question the eval corpus has to answer. Shipping a number that
// wrongly reads as "plenty of detail" would lift a safety cap permanently, on
// every record issued under this version.
//
// Consumers must treat an absent quality as not established, never as maximum.

/**
 * Every similarity fingerprint for one image, plus its quality.
 *
 * Returns null when the file is not an image, because most files registered
 * through this product will not be, and a missing similarity fingerprint is an
 * ordinary state rather than an error.
 */
export async function similarityFingerprints(file) {
  if (!file || !String(file.type || "").startsWith("image/")) return null;
  const pixels = await decode(file);
  const gray = toGrayscale(pixels);
  const { hex: phash } = phashFrom(gray, pixels.width, pixels.height);
  return {
    derivation_version: DERIVATION_VERSION,
    fingerprints: { phash, dhash: dhashFrom(gray, pixels.width, pixels.height) },
  };
}
