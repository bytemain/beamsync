import { blake3Hex, sha256Bytes } from "./crypto.js";

export interface ContentChunk {
  hash: string;
  offset: number;
  length: number;
  data: Uint8Array;
}

export interface FastCdcOptions {
  minSize?: number;
  avgSize?: number;
  maxSize?: number;
}

export const DEFAULT_SMALL_FILE_THRESHOLD_BYTES = 1024 * 1024; // 1 MiB
export const DEFAULT_CDC_MIN_BYTES = 1024 * 1024; // 1 MiB
export const DEFAULT_CDC_AVG_BYTES = 4 * 1024 * 1024; // 4 MiB
export const DEFAULT_CDC_MAX_BYTES = 8 * 1024 * 1024; // 8 MiB

// Deterministic 256-entry 32-bit Gear table derived from SHA-256 constants
const GEAR_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    const seed = new Uint8Array([0x52, 0x46, 0x53, 0x50, i]);
    const digest = sha256Bytes(seed);
    table[i] =
      ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
  }
  return table;
})();

function maskForAvgSize(avgSize: number): { maskS: number; maskL: number } {
  const bits = Math.max(8, Math.min(28, Math.round(Math.log2(avgSize))));
  // Normalized FastCDC: stricter mask before avgSize, looser mask after avgSize
  const bitsS = Math.min(30, bits + 1);
  const bitsL = Math.max(6, bits - 1);
  const makeHighBitMask = (n: number): number => {
    let m = 0;
    for (let i = 0; i < n; i++) {
      m = (m | (1 << (31 - i))) >>> 0;
    }
    return m >>> 0;
  };
  return {
    maskS: makeHighBitMask(bitsS),
    maskL: makeHighBitMask(bitsL),
  };
}

export function fastCdcChunk(
  buffer: Uint8Array,
  options: FastCdcOptions = {},
): ContentChunk[] {
  const minSize = options.minSize ?? DEFAULT_CDC_MIN_BYTES;
  const avgSize = options.avgSize ?? DEFAULT_CDC_AVG_BYTES;
  const maxSize = options.maxSize ?? DEFAULT_CDC_MAX_BYTES;

  if (buffer.length === 0) {
    return [];
  }
  if (buffer.length <= minSize) {
    return [
      {
        hash: blake3Hex(buffer),
        offset: 0,
        length: buffer.length,
        data: buffer,
      },
    ];
  }

  const { maskS, maskL } = maskForAvgSize(avgSize);
  const chunks: ContentChunk[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    const remaining = buffer.length - offset;
    if (remaining <= minSize) {
      const slice = buffer.subarray(offset);
      chunks.push({
        hash: blake3Hex(slice),
        offset,
        length: slice.length,
        data: slice,
      });
      break;
    }

    const limit = Math.min(remaining, maxSize);
    const normalPoint = Math.min(limit, avgSize);
    let fp = 0;
    let cut = limit;

    let i = minSize;
    for (; i < normalPoint; i++) {
      fp = ((fp << 1) + GEAR_TABLE[buffer[offset + i]]) >>> 0;
      if ((fp & maskS) === 0) {
        cut = i;
        break;
      }
    }

    if (cut === limit) {
      for (; i < limit; i++) {
        fp = ((fp << 1) + GEAR_TABLE[buffer[offset + i]]) >>> 0;
        if ((fp & maskL) === 0) {
          cut = i;
          break;
        }
      }
    }

    const slice = buffer.subarray(offset, offset + cut);
    chunks.push({
      hash: blake3Hex(slice),
      offset,
      length: slice.length,
      data: slice,
    });
    offset += cut;
  }

  return chunks;
}
