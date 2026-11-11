import {
  lstat,
  mkdir,
  readdir,
  readFile,
  readlink,
  realpath,
  rename,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  blake3Hex,
  canonicalizeManifest,
  computeRootTreeDigest,
  DEFAULT_SMALL_FILE_THRESHOLD_BYTES,
  fastCdcChunk,
  IgnoreMatcher,
  utf8Bytes,
  validateRelativeSymlinkTarget,
  type FastCdcOptions,
  type FileChunkRef,
  type ManifestEntry,
  type TreeManifest,
} from "@beamsync/protocol";

export interface BlobDiskSlice {
  absPath: string;
  offset: number;
  length: number;
  mode: number;
}

interface CachedFileIndexEntry {
  size: number;
  mtimeMs: number;
  ino: number;
  mode: number;
  blobHash?: string;
  chunks?: FileChunkRef[];
}

interface PersistedIndexFile {
  version: 1;
  rootPath: string;
  entries: Record<string, CachedFileIndexEntry>;
}

export interface ScanWorkspaceOptions {
  cacheDir?: string;
  extraIgnoreRules?: string[];
  smallFileThresholdBytes?: number;
  cdcOptions?: FastCdcOptions;
}

export interface ScanWorkspaceResult {
  rootPath: string;
  manifest: TreeManifest;
  rootTreeDigest: string;
  blobSlices: Map<string, BlobDiskSlice>;
  cachedFileHits: number;
  hashedFiles: number;
}

export async function scanWorkspace(
  dirPath: string,
  options: ScanWorkspaceOptions = {},
): Promise<ScanWorkspaceResult> {
  const resolvedRoot = await realpath(dirPath).catch(() => path.resolve(dirPath));
  const cacheDir =
    options.cacheDir ?? path.join(os.homedir(), ".cache", "beamsync", "indexes");
  await mkdir(cacheDir, { recursive: true });

  const indexKey = blake3Hex(utf8Bytes(resolvedRoot)).slice(0, 32);
  const indexFilePath = path.join(cacheDir, `${indexKey}.json`);

  let previousEntries: Record<string, CachedFileIndexEntry> = {};
  try {
    const raw = await readFile(indexFilePath, "utf8");
    const parsed = JSON.parse(raw) as PersistedIndexFile;
    if (parsed.version === 1 && parsed.entries) {
      previousEntries = parsed.entries;
    }
  } catch {
    // Fresh cache
  }

  const ignoreLines: string[] = [...(options.extraIgnoreRules ?? [])];
  for (const ignoreFile of [".beamsyncignore", ".syncignore"]) {
    try {
      const content = await readFile(path.join(resolvedRoot, ignoreFile), "utf8");
      ignoreLines.push(...content.split(/\r?\n/));
    } catch {
      // Optional ignore file
    }
  }
  const matcher = new IgnoreMatcher(ignoreLines);

  const smallThreshold =
    options.smallFileThresholdBytes ?? DEFAULT_SMALL_FILE_THRESHOLD_BYTES;

  const entries: ManifestEntry[] = [];
  const nextCache: Record<string, CachedFileIndexEntry> = {};
  const blobSlices = new Map<string, BlobDiskSlice>();
  const hardlinkMap = new Map<string, string>(); // `${dev}:${ino}` -> groupId
  let totalLogicalBytes = 0;
  let cachedFileHits = 0;
  let hashedFiles = 0;

  async function walk(currentAbs: string, currentRel: string): Promise<boolean> {
    const dirents = await readdir(currentAbs, { withFileTypes: true });
    dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

    let hasIncludedChildren = false;
    for (const d of dirents) {
      const childRel = currentRel ? `${currentRel}/${d.name}` : d.name;
      if (matcher.ignores(childRel)) {
        continue;
      }
      const childAbs = path.join(currentAbs, d.name);
      const st = await lstat(childAbs);

      if (st.isDirectory()) {
        hasIncludedChildren = true;
        const childHadChildren = await walk(childAbs, childRel);
        if (!childHadChildren) {
          entries.push({
            kind: "dir",
            relPath: childRel,
            mode: st.mode & 0o777,
            mtimeMs: Math.round(st.mtimeMs),
          });
        }
        continue;
      }

      if (st.isSymbolicLink()) {
        hasIncludedChildren = true;
        const linkTarget = await readlink(childAbs);
        validateRelativeSymlinkTarget(childRel, linkTarget);
        entries.push({
          kind: "symlink",
          relPath: childRel,
          linkTarget: linkTarget.replace(/\\/g, "/"),
          mtimeMs: Math.round(st.mtimeMs),
        });
        continue;
      }

      if (st.isFile()) {
        hasIncludedChildren = true;
        const size = st.size;
        const mtimeMs = Math.round(st.mtimeMs);
        const mode = st.mode & 0o777;
        const ino = Number(st.ino);
        totalLogicalBytes += size;

        let hardlinkGroupId: string | undefined;
        if (st.nlink > 1) {
          const hlKey = `${st.dev}:${st.ino}`;
          let gid = hardlinkMap.get(hlKey);
          if (!gid) {
            gid = blake3Hex(utf8Bytes(`hl:${childRel}`)).slice(0, 16);
            hardlinkMap.set(hlKey, gid);
          }
          hardlinkGroupId = gid;
        }

        if (size === 0) {
          entries.push({
            kind: "file",
            relPath: childRel,
            size: 0,
            mode,
            mtimeMs,
            hardlinkGroupId,
          });
          nextCache[childRel] = { size: 0, mtimeMs, ino, mode };
          continue;
        }

        const cached = previousEntries[childRel];
        if (
          cached &&
          cached.size === size &&
          cached.mtimeMs === mtimeMs &&
          cached.ino === ino &&
          (cached.blobHash || cached.chunks)
        ) {
          cachedFileHits++;
          nextCache[childRel] = { ...cached, mode };
          if (cached.blobHash) {
            if (!blobSlices.has(cached.blobHash)) {
              blobSlices.set(cached.blobHash, {
                absPath: childAbs,
                offset: 0,
                length: size,
                mode,
              });
            }
          } else if (cached.chunks) {
            for (const ch of cached.chunks) {
              if (!blobSlices.has(ch.hash)) {
                blobSlices.set(ch.hash, {
                  absPath: childAbs,
                  offset: ch.offset,
                  length: ch.length,
                  mode,
                });
              }
            }
          }
          entries.push({
            kind: "file",
            relPath: childRel,
            size,
            mode,
            mtimeMs,
            blobHash: cached.blobHash,
            chunks: cached.chunks,
            hardlinkGroupId,
          });
          continue;
        }

        // Read & hash new or modified file
        hashedFiles++;
        const buf = await readFile(childAbs);
        const u8 = new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);

        if (size <= smallThreshold) {
          const blobHash = blake3Hex(u8);
          if (!blobSlices.has(blobHash)) {
            blobSlices.set(blobHash, {
              absPath: childAbs,
              offset: 0,
              length: size,
              mode,
            });
          }
          nextCache[childRel] = { size, mtimeMs, ino, mode, blobHash };
          entries.push({
            kind: "file",
            relPath: childRel,
            size,
            mode,
            mtimeMs,
            blobHash,
            hardlinkGroupId,
          });
        } else {
          const cdcChunks = fastCdcChunk(u8, options.cdcOptions);
          const chunkRefs: FileChunkRef[] = cdcChunks.map((c) => {
            if (!blobSlices.has(c.hash)) {
              blobSlices.set(c.hash, {
                absPath: childAbs,
                offset: c.offset,
                length: c.length,
                mode,
              });
            }
            return {
              hash: c.hash,
              offset: c.offset,
              length: c.length,
            };
          });
          nextCache[childRel] = { size, mtimeMs, ino, mode, chunks: chunkRefs };
          entries.push({
            kind: "file",
            relPath: childRel,
            size,
            mode,
            mtimeMs,
            chunks: chunkRefs,
            hardlinkGroupId,
          });
        }
      }
    }
    return hasIncludedChildren;
  }

  await walk(resolvedRoot, "");

  const manifest = canonicalizeManifest({
    version: "beamsync-tree/v1",
    totalLogicalBytes,
    entries,
  });
  const rootTreeDigest = computeRootTreeDigest(manifest);

  const tmpIndex = `${indexFilePath}.tmp-${process.pid}`;
  const indexPayload: PersistedIndexFile = {
    version: 1,
    rootPath: resolvedRoot,
    entries: nextCache,
  };
  await writeFile(tmpIndex, JSON.stringify(indexPayload), "utf8");
  await rename(tmpIndex, indexFilePath);

  return {
    rootPath: resolvedRoot,
    manifest,
    rootTreeDigest,
    blobSlices,
    cachedFileHits,
    hashedFiles,
  };
}
