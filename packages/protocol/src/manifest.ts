import { blake3 } from "@noble/hashes/blake3";
import { bytesToHex, utf8Bytes } from "./crypto.js";

export interface FileChunkRef {
  hash: string;
  offset: number;
  length: number;
}

export interface ManifestFileEntry {
  kind: "file";
  relPath: string;
  size: number;
  mode: number;
  mtimeMs: number;
  blobHash?: string; // Present when size > 0 and single-blob
  chunks?: FileChunkRef[]; // Present when chunked via FastCDC
  hardlinkGroupId?: string;
}

export interface ManifestSymlinkEntry {
  kind: "symlink";
  relPath: string;
  linkTarget: string;
  mtimeMs: number;
}

export interface ManifestDirEntry {
  kind: "dir";
  relPath: string;
  mode: number;
  mtimeMs: number;
}

export type ManifestEntry =
  | ManifestFileEntry
  | ManifestSymlinkEntry
  | ManifestDirEntry;

export interface TreeManifest {
  version: "beamsync-tree/v1";
  entries: ManifestEntry[];
  totalLogicalBytes: number;
}

export function normalizeRelPath(relPath: string): string {
  const slashNormalized = relPath.replace(/\\/g, "/").replace(/^\/+/, "");
  if (!slashNormalized || slashNormalized === ".") {
    throw new Error("Empty relative path is not allowed in manifest");
  }
  const segments = slashNormalized.split("/");
  for (const seg of segments) {
    if (!seg || seg === "." || seg === "..") {
      throw new Error(`Unsafe relative path segment in "${relPath}"`);
    }
  }
  return segments.join("/");
}

export function validateRelativeSymlinkTarget(
  relPath: string,
  linkTarget: string,
): void {
  const normalizedTarget = linkTarget.replace(/\\/g, "/");
  if (normalizedTarget.startsWith("/")) {
    throw new Error(
      `Absolute symlink target "${linkTarget}" at "${relPath}" is rejected outside full-disk mode`,
    );
  }
  const parentParts = normalizeRelPath(relPath).split("/").slice(0, -1);
  const stack = [...parentParts];
  for (const part of normalizedTarget.split("/")) {
    if (!part || part === ".") continue;
    if (part === "..") {
      if (stack.length === 0) {
        throw new Error(
          `Symlink "${relPath}" -> "${linkTarget}" escapes workspace root`,
        );
      }
      stack.pop();
    } else {
      stack.push(part);
    }
  }
}

export function canonicalizeManifest(manifest: TreeManifest): TreeManifest {
  const sorted = [...manifest.entries].sort((a, b) =>
    a.relPath < b.relPath ? -1 : a.relPath > b.relPath ? 1 : 0,
  );
  return {
    version: "beamsync-tree/v1",
    totalLogicalBytes: manifest.totalLogicalBytes,
    entries: sorted,
  };
}

function digestProjection(entry: ManifestEntry): unknown {
  // Exclude volatile mtimeMs on directories so identical directory trees hash deterministically,
  // while keeping file content hashes, modes, hardlinks, and symlink targets strictly bound.
  if (entry.kind === "file") {
    return {
      k: "f",
      p: entry.relPath,
      s: entry.size,
      m: entry.mode & 0o777,
      b: entry.blobHash ?? null,
      c: entry.chunks ?? null,
      h: entry.hardlinkGroupId ?? null,
    };
  }
  if (entry.kind === "symlink") {
    return {
      k: "l",
      p: entry.relPath,
      t: entry.linkTarget,
    };
  }
  return {
    k: "d",
    p: entry.relPath,
    m: entry.mode & 0o777,
  };
}

const DIGEST_BATCH_ENTRIES = 4096;

/**
 * BLAKE3 over the JSON array of every entry's digest projection, in canonical path order.
 * The array is hashed in batches, so a tree with millions of entries never has to exist as
 * one string.
 */
export function computeRootTreeDigest(manifest: TreeManifest): string {
  const entries = canonicalizeManifest(manifest).entries;
  const hasher = blake3.create({});
  hasher.update(utf8Bytes("["));
  for (let start = 0; start < entries.length; start += DIGEST_BATCH_ENTRIES) {
    const batch: unknown[] = [];
    const end = Math.min(entries.length, start + DIGEST_BATCH_ENTRIES);
    for (let i = start; i < end; i++) {
      batch.push(digestProjection(entries[i]));
    }
    // "[a,b,c]" without its brackets is exactly this batch's share of the full array
    const json = JSON.stringify(batch);
    hasher.update(utf8Bytes((start > 0 ? "," : "") + json.slice(1, -1)));
  }
  hasher.update(utf8Bytes("]"));
  return bytesToHex(hasher.digest());
}

export function collectRequiredBlobHashes(manifest: TreeManifest): Set<string> {
  const hashes = new Set<string>();
  for (const entry of manifest.entries) {
    if (entry.kind !== "file" || entry.size === 0) continue;
    if (entry.blobHash) {
      hashes.add(entry.blobHash);
    }
    if (entry.chunks) {
      for (const ch of entry.chunks) {
        hashes.add(ch.hash);
      }
    }
  }
  return hashes;
}

