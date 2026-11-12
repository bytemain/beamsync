import { aeadDecrypt, aeadEncrypt, utf8Bytes } from "./crypto.js";
import type { IgnoreSpec } from "./ignore.js";
import type { ManifestEntry, TreeManifest } from "./manifest.js";

/**
 * Sealed control streams carry peer-to-peer control data that does not fit in (or should not be
 * readable from) a single signaling message: the tree manifest and the target's known blob list.
 *
 * A stream is a byte stream cut into segments. Each segment is zstd-compressed, then sealed with
 * the session's control key. The Coordinator forwards segments without being able to read them,
 * and the segment index and end-of-stream marker are bound into the AEAD associated data, so it
 * cannot reorder, drop, truncate or splice segments without the receiver noticing.
 */
export type ControlStreamName = "manifest" | "have_blobs";

export const CONTROL_STREAM_NAMES: readonly ControlStreamName[] = ["manifest", "have_blobs"];

/** Which peer writes each stream; the other peer is the only one allowed to acknowledge it. */
export const CONTROL_STREAM_WRITER_ROLE: Record<ControlStreamName, "source" | "target"> = {
  manifest: "source",
  have_blobs: "target",
};

/** Uncompressed bytes per segment. */
export const CONTROL_STREAM_SEGMENT_BYTES = 1024 * 1024;

/** How many segments a writer may have in flight before it waits for the reader. */
export const CONTROL_STREAM_WINDOW_SEGMENTS = 8;

/** A reader refuses segments that decompress to more than this. */
export const CONTROL_STREAM_MAX_SEGMENT_RAW_BYTES = 64 * 1024 * 1024;

const SEALED_OVERHEAD_BYTES = 12 + 16; // nonce + tag
const ENVELOPE_RESERVE_BYTES = 512; // JSON field names, stream name, index, cseq
const ZSTD_WORST_CASE_EXPANSION_BYTES = 256;

export function isControlStreamName(value: unknown): value is ControlStreamName {
  return value === "manifest" || value === "have_blobs";
}

/**
 * Largest segment size whose sealed, base64-encoded form is guaranteed to fit in one signaling
 * message of `maxMessageBytes`, even if the data is incompressible.
 */
export function controlStreamSegmentBytesFor(
  maxMessageBytes: number,
  preferredBytes = CONTROL_STREAM_SEGMENT_BYTES,
): number {
  const base64Budget = maxMessageBytes - ENVELOPE_RESERVE_BYTES;
  const sealedBudget = Math.floor(base64Budget / 4) * 3;
  const rawBudget = sealedBudget - SEALED_OVERHEAD_BYTES - ZSTD_WORST_CASE_EXPANSION_BYTES;
  if (rawBudget < 256) {
    throw new Error(
      `Signaling message limit of ${maxMessageBytes} bytes is too small to carry a control stream`,
    );
  }
  return Math.max(256, Math.min(Math.floor(preferredBytes), rawBudget));
}

function segmentAad(
  sessionId: string,
  stream: ControlStreamName,
  index: number,
  final: boolean,
): Uint8Array {
  return utf8Bytes(
    `beamsync/control-stream/v1:${sessionId}:${stream}:${index}:${final ? "final" : "more"}`,
  );
}

export interface ControlStreamSegmentContext {
  controlKey: Uint8Array;
  sessionId: string;
  stream: ControlStreamName;
  index: number;
  final: boolean;
}

export async function sealControlStreamSegment(
  ctx: ControlStreamSegmentContext,
  raw: Uint8Array,
  zstdCompressFn: (raw: Uint8Array) => Promise<Uint8Array> | Uint8Array,
): Promise<Uint8Array> {
  const compressed = await zstdCompressFn(raw);
  return aeadEncrypt(
    ctx.controlKey,
    compressed,
    segmentAad(ctx.sessionId, ctx.stream, ctx.index, ctx.final),
  );
}

export async function openControlStreamSegment(
  ctx: ControlStreamSegmentContext,
  sealed: Uint8Array,
  zstdDecompressFn: (compressed: Uint8Array) => Promise<Uint8Array> | Uint8Array,
): Promise<Uint8Array> {
  let compressed: Uint8Array;
  try {
    compressed = aeadDecrypt(
      ctx.controlKey,
      sealed,
      segmentAad(ctx.sessionId, ctx.stream, ctx.index, ctx.final),
    );
  } catch {
    throw new Error(
      `CONTROL_STREAM_INTEGRITY: segment ${ctx.index} of "${ctx.stream}" failed authentication ` +
        `(altered, reordered or truncated in transit)`,
    );
  }
  const raw = await zstdDecompressFn(compressed);
  if (raw.byteLength > CONTROL_STREAM_MAX_SEGMENT_RAW_BYTES) {
    throw new Error(
      `CONTROL_STREAM_INTEGRITY: segment ${ctx.index} of "${ctx.stream}" expands to ${raw.byteLength} bytes`,
    );
  }
  return raw;
}

/**
 * Reassembles newline-delimited records from segments that were cut at arbitrary byte offsets,
 * including in the middle of a multi-byte UTF-8 sequence.
 */
export class ControlStreamLineSplitter {
  private carry: Uint8Array[] = [];
  private carryBytes = 0;
  private readonly decoder = new TextDecoder("utf-8", { fatal: true });

  push(segment: Uint8Array, onLine: (line: string) => void): void {
    let start = 0;
    for (;;) {
      const nl = segment.indexOf(0x0a, start);
      if (nl < 0) break;
      const piece = segment.subarray(start, nl);
      if (this.carryBytes > 0) {
        this.carry.push(piece);
        const joined = new Uint8Array(this.carryBytes + piece.byteLength);
        let offset = 0;
        for (const part of this.carry) {
          joined.set(part, offset);
          offset += part.byteLength;
        }
        this.carry = [];
        this.carryBytes = 0;
        onLine(this.decoder.decode(joined));
      } else {
        onLine(this.decoder.decode(piece));
      }
      start = nl + 1;
    }
    if (start < segment.byteLength) {
      // Copy: the caller may reuse or release the segment buffer
      const rest = segment.slice(start);
      this.carry.push(rest);
      this.carryBytes += rest.byteLength;
    }
  }

  /** Every record ends with a newline, so leftover bytes mean the stream was cut short. */
  finish(): void {
    if (this.carryBytes > 0) {
      throw new Error("CONTROL_STREAM_INTEGRITY: stream ended in the middle of a record");
    }
  }
}

/** First record of the `manifest` stream; every following record is one `ManifestEntry`. */
export interface ManifestStreamHeader {
  version: "beamsync-manifest-stream/v1";
  treeVersion: TreeManifest["version"];
  totalLogicalBytes: number;
  entryCount: number;
  rootTreeDigest: string;
  /**
   * Ignore rules the source applied. The target uses them to keep its own copies of paths the
   * source skipped instead of deleting them.
   */
  ignoreSpec?: IgnoreSpec;
}

export function buildManifestStreamHeader(
  manifest: TreeManifest,
  rootTreeDigest: string,
  ignoreSpec?: IgnoreSpec,
): ManifestStreamHeader {
  return {
    version: "beamsync-manifest-stream/v1",
    treeVersion: manifest.version,
    totalLogicalBytes: manifest.totalLogicalBytes,
    entryCount: manifest.entries.length,
    rootTreeDigest,
    ignoreSpec,
  };
}

/** Records of the `manifest` stream: the header, then one entry per record. */
export function* manifestStreamRecords(
  manifest: TreeManifest,
  rootTreeDigest: string,
  ignoreSpec?: IgnoreSpec,
): Generator<string> {
  yield JSON.stringify(buildManifestStreamHeader(manifest, rootTreeDigest, ignoreSpec));
  for (const entry of manifest.entries) {
    yield JSON.stringify(entry);
  }
}

/** Collects the records of a `manifest` stream back into a manifest. */
export class ManifestStreamAssembler {
  private header: ManifestStreamHeader | null = null;
  private readonly entries: ManifestEntry[] = [];

  acceptRecord(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      throw new Error("MANIFEST_INTEGRITY: manifest stream record is not valid JSON");
    }
    if (!parsed || typeof parsed !== "object") {
      throw new Error("MANIFEST_INTEGRITY: manifest stream record is not an object");
    }
    if (!this.header) {
      const header = parsed as Partial<ManifestStreamHeader>;
      if (
        header.version !== "beamsync-manifest-stream/v1" ||
        header.treeVersion !== "beamsync-tree/v1" ||
        typeof header.rootTreeDigest !== "string" ||
        !Number.isSafeInteger(header.entryCount) ||
        (header.entryCount as number) < 0 ||
        !Number.isSafeInteger(header.totalLogicalBytes) ||
        (header.totalLogicalBytes as number) < 0
      ) {
        throw new Error("MANIFEST_INTEGRITY: unsupported or malformed manifest stream header");
      }
      this.header = header as ManifestStreamHeader;
      return;
    }
    const entry = parsed as Partial<ManifestEntry>;
    if (
      (entry.kind !== "file" && entry.kind !== "symlink" && entry.kind !== "dir") ||
      typeof entry.relPath !== "string"
    ) {
      throw new Error("MANIFEST_INTEGRITY: malformed manifest entry");
    }
    if (this.entries.length >= this.header.entryCount) {
      throw new Error(
        `MANIFEST_INTEGRITY: manifest stream carries more than the announced ${this.header.entryCount} entries`,
      );
    }
    this.entries.push(entry as ManifestEntry);
  }

  get receivedEntries(): number {
    return this.entries.length;
  }

  finish(): { header: ManifestStreamHeader; manifest: TreeManifest } {
    if (!this.header) {
      throw new Error("MANIFEST_INTEGRITY: manifest stream ended before its header");
    }
    if (this.entries.length !== this.header.entryCount) {
      throw new Error(
        `MANIFEST_INTEGRITY: manifest stream carried ${this.entries.length} of ${this.header.entryCount} entries`,
      );
    }
    return {
      header: this.header,
      manifest: {
        version: this.header.treeVersion,
        totalLogicalBytes: this.header.totalLogicalBytes,
        entries: this.entries,
      },
    };
  }
}

const BLOB_HASH_PATTERN = /^[0-9a-f]{64}$/;

/** Records of the `have_blobs` stream: the number of hashes, then one blob hash per record. */
export function* haveBlobsStreamRecords(
  hashes: Iterable<string>,
  count: number,
): Generator<string> {
  yield String(count);
  yield* hashes;
}

/** Collects the records of a `have_blobs` stream back into a set of blob hashes. */
export class HaveBlobsStreamAssembler {
  private announced: number | null = null;
  private readonly hashes = new Set<string>();

  acceptRecord(line: string): void {
    if (this.announced === null) {
      const count = Number(line);
      if (!/^\d+$/.test(line) || !Number.isSafeInteger(count)) {
        throw new Error("CONTROL_STREAM_INTEGRITY: malformed have_blobs stream header");
      }
      this.announced = count;
      return;
    }
    if (!BLOB_HASH_PATTERN.test(line)) {
      throw new Error("CONTROL_STREAM_INTEGRITY: malformed blob hash in have_blobs stream");
    }
    this.hashes.add(line);
  }

  finish(): Set<string> {
    if (this.announced === null) {
      throw new Error("CONTROL_STREAM_INTEGRITY: have_blobs stream ended before its header");
    }
    if (this.hashes.size !== this.announced) {
      throw new Error(
        `CONTROL_STREAM_INTEGRITY: have_blobs stream carried ${this.hashes.size} of ${this.announced} hashes`,
      );
    }
    return this.hashes;
  }
}
