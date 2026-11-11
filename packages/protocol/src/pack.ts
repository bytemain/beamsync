import { decompress as fzstdDecompress } from "fzstd";
import {
  aeadDecrypt,
  aeadEncrypt,
  aeadEncryptConvergent,
  blake3Hex,
  concatBytes,
  utf8Bytes,
} from "./crypto.js";

export type PackCompressionMode = "none" | "zstd";
export type PackEncryptionMode = "none" | "chacha20-poly1305";

export interface PackBlobInput {
  hash: string;
  data: Uint8Array;
}

export interface PackIndexEntry {
  hash: string;
  offset: number;
  length: number;
}

export interface EncodedPack {
  packId: string;
  wireBytes: Uint8Array;
  uncompressedBytes: number;
  blobCount: number;
  entries: PackIndexEntry[];
}

export interface DecodedPack {
  packId: string;
  compression: PackCompressionMode;
  encryption: PackEncryptionMode;
  blobs: Array<{ hash: string; data: Uint8Array }>;
}

const MAGIC = new Uint8Array([0x42, 0x4d, 0x53, 0x50]); // "BMSP"
const FORMAT_VERSION = 1;
const decoder = new TextDecoder();

export interface EncodePackOptions {
  compression: PackCompressionMode;
  encryption: PackEncryptionMode;
  packKey?: Uint8Array;
  convergent?: boolean;
  zstdCompressFn?: (raw: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

export interface DecodePackOptions {
  packKey?: Uint8Array;
  expectedPackId?: string;
  zstdDecompressFn?: (compressed: Uint8Array) => Promise<Uint8Array> | Uint8Array;
}

/**
 * Binary Pack container layout:
 * - Bytes 0..3: Magic "BMSP"
 * - Byte 4: Version (1)
 * - Byte 5: Compression (0 = none, 1 = zstd)
 * - Byte 6: Encryption (0 = none, 1 = chacha20-poly1305)
 * - Byte 7: Reserved (0)
 * - Bytes 8..N: Inner payload (optionally compressed, then optionally AEAD-sealed with header bytes 0..7 as AAD)
 *
 * Inner payload layout:
 * - 4 bytes BE uint32: JSON index byte length
 * - JSON index UTF-8 bytes: PackIndexEntry[]
 * - Concatenated raw blob bytes
 */
export async function encodePack(
  blobs: PackBlobInput[],
  options: EncodePackOptions,
): Promise<EncodedPack> {
  const entries: PackIndexEntry[] = [];
  let offset = 0;
  const deduped: Uint8Array[] = [];
  const seen = new Set<string>();

  for (const blob of blobs) {
    if (seen.has(blob.hash)) continue;
    seen.add(blob.hash);
    entries.push({
      hash: blob.hash,
      offset,
      length: blob.data.length,
    });
    deduped.push(blob.data);
    offset += blob.data.length;
  }

  const indexBytes = utf8Bytes(JSON.stringify(entries));
  const indexLenBuf = new Uint8Array(4);
  new DataView(indexLenBuf.buffer).setUint32(0, indexBytes.length, false);

  const innerPlain = concatBytes(indexLenBuf, indexBytes, ...deduped);

  let processed = innerPlain;
  const compCode = options.compression === "zstd" ? 1 : 0;
  if (options.compression === "zstd") {
    if (!options.zstdCompressFn) {
      throw new Error("zstdCompressFn is required when compression is 'zstd'");
    }
    processed = await options.zstdCompressFn(innerPlain);
  }

  const encCode = options.encryption === "chacha20-poly1305" ? 1 : 0;
  const header = new Uint8Array([
    MAGIC[0],
    MAGIC[1],
    MAGIC[2],
    MAGIC[3],
    FORMAT_VERSION,
    compCode,
    encCode,
    0,
  ]);

  if (options.encryption === "chacha20-poly1305") {
    if (!options.packKey || options.packKey.length !== 32) {
      throw new Error("32-byte packKey is required when encryption is enabled");
    }
    processed = options.convergent
      ? aeadEncryptConvergent(options.packKey, processed, header)
      : aeadEncrypt(options.packKey, processed, header);
  }

  const wireBytes = concatBytes(header, processed);
  const packId = blake3Hex(wireBytes);

  return {
    packId,
    wireBytes,
    uncompressedBytes: offset,
    blobCount: entries.length,
    entries,
  };
}

export async function decodePack(
  wireBytes: Uint8Array,
  options: DecodePackOptions = {},
): Promise<DecodedPack> {
  if (wireBytes.length < 12) {
    throw new Error("Pack payload too small");
  }
  for (let i = 0; i < 4; i++) {
    if (wireBytes[i] !== MAGIC[i]) {
      throw new Error("Invalid pack magic header");
    }
  }
  const version = wireBytes[4];
  if (version !== FORMAT_VERSION) {
    throw new Error(`Unsupported pack version: ${version}`);
  }

  const packId = blake3Hex(wireBytes);
  if (options.expectedPackId && options.expectedPackId !== packId) {
    throw new Error(
      `Pack digest mismatch: expected ${options.expectedPackId}, got ${packId}`,
    );
  }

  const compression: PackCompressionMode = wireBytes[5] === 1 ? "zstd" : "none";
  const encryption: PackEncryptionMode =
    wireBytes[6] === 1 ? "chacha20-poly1305" : "none";
  const header = wireBytes.subarray(0, 8);
  let body = wireBytes.subarray(8);

  if (encryption === "chacha20-poly1305") {
    if (!options.packKey || options.packKey.length !== 32) {
      throw new Error("Pack is encrypted but no 32-byte packKey was provided");
    }
    body = aeadDecrypt(options.packKey, body, header);
  }

  if (compression === "zstd") {
    if (options.zstdDecompressFn) {
      body = await options.zstdDecompressFn(body);
    } else {
      body = fzstdDecompress(body);
    }
  }

  if (body.length < 4) {
    throw new Error("Corrupted inner pack header");
  }
  const indexLen = new DataView(
    body.buffer,
    body.byteOffset,
    body.byteLength,
  ).getUint32(0, false);

  if (4 + indexLen > body.length) {
    throw new Error("Corrupted pack index length");
  }

  const indexJson = decoder.decode(body.subarray(4, 4 + indexLen));
  const entries = JSON.parse(indexJson) as PackIndexEntry[];
  const dataRegion = body.subarray(4 + indexLen);

  const blobs: Array<{ hash: string; data: Uint8Array }> = [];
  for (const entry of entries) {
    if (entry.offset < 0 || entry.offset + entry.length > dataRegion.length) {
      throw new Error(`Out-of-bounds blob slice in pack for ${entry.hash}`);
    }
    const slice = dataRegion.subarray(entry.offset, entry.offset + entry.length);
    const actualHash = blake3Hex(slice);
    if (actualHash !== entry.hash) {
      throw new Error(
        `Blob digest mismatch inside pack: expected ${entry.hash}, got ${actualHash}`,
      );
    }
    blobs.push({ hash: entry.hash, data: slice });
  }

  return {
    packId,
    compression,
    encryption,
    blobs,
  };
}
