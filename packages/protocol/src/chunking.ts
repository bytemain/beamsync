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

interface ResolvedCdcParams {
  minSize: number;
  maxSize: number;
  avgSize: number;
  maskS: number;
  maskL: number;
}

function resolveCdcParams(options: FastCdcOptions): ResolvedCdcParams {
  const minSize = options.minSize ?? DEFAULT_CDC_MIN_BYTES;
  const avgSize = options.avgSize ?? DEFAULT_CDC_AVG_BYTES;
  const maxSize = options.maxSize ?? DEFAULT_CDC_MAX_BYTES;
  return { minSize, avgSize, maxSize, ...maskForAvgSize(avgSize) };
}

/**
 * Length of the chunk that starts at `offset`, given that `remaining` bytes of content follow
 * it. Only the first `min(remaining, maxSize)` bytes after `offset` are inspected, so a caller
 * that holds at least `maxSize` bytes (and more than `minSize`) gets the same answer as one
 * that holds the whole content.
 */
function nextChunkLength(
  buffer: Uint8Array,
  offset: number,
  remaining: number,
  p: ResolvedCdcParams,
): number {
  if (remaining <= p.minSize) return remaining;

  const limit = Math.min(remaining, p.maxSize);
  const normalPoint = Math.min(limit, p.avgSize);
  let fp = 0;
  let cut = limit;

  let i = p.minSize;
  for (; i < normalPoint; i++) {
    fp = ((fp << 1) + GEAR_TABLE[buffer[offset + i]]) >>> 0;
    if ((fp & p.maskS) === 0) {
      cut = i;
      break;
    }
  }

  if (cut === limit) {
    for (; i < limit; i++) {
      fp = ((fp << 1) + GEAR_TABLE[buffer[offset + i]]) >>> 0;
      if ((fp & p.maskL) === 0) {
        cut = i;
        break;
      }
    }
  }

  // A zero-length chunk would never advance
  return Math.max(cut, 1);
}

export function fastCdcChunk(
  buffer: Uint8Array,
  options: FastCdcOptions = {},
): ContentChunk[] {
  const p = resolveCdcParams(options);
  const chunks: ContentChunk[] = [];
  let offset = 0;
  while (offset < buffer.length) {
    const length = nextChunkLength(buffer, offset, buffer.length - offset, p);
    const slice = buffer.subarray(offset, offset + length);
    chunks.push({ hash: blake3Hex(slice), offset, length, data: slice });
    offset += length;
  }
  return chunks;
}

export interface ContentChunkRef {
  hash: string;
  offset: number;
  length: number;
}

/**
 * Incremental FastCDC: content is pushed in pieces of any size and chunk boundaries come out
 * identical to `fastCdcChunk` over the concatenation. Holds a fixed buffer of two maximum-size
 * chunks, independent of the total content length.
 */
export class FastCdcStreamChunker {
  private readonly p: ResolvedCdcParams;
  /** Buffered bytes needed before a boundary can be decided without knowing where the content ends. */
  private readonly decideBytes: number;
  private buf: Uint8Array;
  private start = 0;
  private end = 0;
  /** Offset of `buf[start]` within the whole content. */
  private contentOffset = 0;
  private finished = false;

  constructor(options: FastCdcOptions = {}) {
    this.p = resolveCdcParams(options);
    this.decideBytes = Math.max(this.p.maxSize, this.p.minSize + 1);
    this.buf = new Uint8Array(this.decideBytes * 2);
  }

  /** Bytes pushed so far that have not been emitted as a chunk yet. */
  get bufferedBytes(): number {
    return this.end - this.start;
  }

  push(data: Uint8Array): ContentChunkRef[] {
    if (this.finished) throw new Error("FastCdcStreamChunker: push after finish");
    const out: ContentChunkRef[] = [];
    let consumed = 0;
    while (consumed < data.length) {
      // Top up to just what one decision needs, so the buffer never has to grow
      const want = Math.min(data.length - consumed, this.decideBytes - this.bufferedBytes);
      this.append(data.subarray(consumed, consumed + want));
      consumed += want;
      if (this.bufferedBytes >= this.decideBytes) this.emit(out, this.bufferedBytes);
    }
    return out;
  }

  finish(): ContentChunkRef[] {
    if (this.finished) throw new Error("FastCdcStreamChunker: finish called twice");
    this.finished = true;
    const out: ContentChunkRef[] = [];
    while (this.bufferedBytes > 0) this.emit(out, this.bufferedBytes);
    return out;
  }

  private emit(out: ContentChunkRef[], remaining: number): void {
    const length = nextChunkLength(this.buf, this.start, remaining, this.p);
    out.push({
      hash: blake3Hex(this.buf.subarray(this.start, this.start + length)),
      offset: this.contentOffset,
      length,
    });
    this.start += length;
    this.contentOffset += length;
  }

  private append(data: Uint8Array): void {
    if (this.end + data.length > this.buf.length) {
      this.buf.copyWithin(0, this.start, this.end);
      this.end -= this.start;
      this.start = 0;
    }
    this.buf.set(data, this.end);
    this.end += data.length;
  }
}
