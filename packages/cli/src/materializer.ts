import {
  chmod,
  copyFile,
  link,
  lstat,
  mkdir,
  open,
  readdir,
  rename,
  rm,
  stat,
  symlink,
  truncate,
  unlink,
  utimes,
  writeFile,
} from "node:fs/promises";
import path from "node:path";
import {
  LayeredIgnoreMatcher,
  validateRelativeSymlinkTarget,
  type IgnoreSpec,
  type ManifestFileEntry,
  type TreeManifest,
} from "@beamsync/protocol";
import type { BlobDiskSlice } from "./stateIndex.js";

interface WholeFileTarget {
  kind: "whole";
  stagedPath: string;
}

interface ChunkSliceTarget {
  kind: "chunk";
  stagedPath: string;
  offset: number;
  length: number;
}

type BlobPlacement = WholeFileTarget | ChunkSliceTarget;

export interface CommitResult {
  committedFiles: number;
  /** Paths the source ignored that were carried over from the previous target tree. */
  preservedIgnoredPaths: number;
  /** Paths that should have been carried over but could not be moved. */
  preserveFailures: Array<{ relPath: string; error: string }>;
  /** Previous target tree, kept on disk because a carry-over failed. */
  retainedBackupDir?: string;
}

/** Validates rules received from the other peer and compiles them; null when there are none. */
function buildCarryOverMatcher(spec: IgnoreSpec): LayeredIgnoreMatcher | null {
  const kinds = ["from", "file", "explicit"];
  const valid =
    spec !== null &&
    typeof spec === "object" &&
    spec.version === 1 &&
    Array.isArray(spec.layers) &&
    spec.layers.every(
      (l) =>
        l !== null &&
        typeof l === "object" &&
        kinds.includes(l.kind) &&
        typeof l.source === "string" &&
        typeof l.baseDir === "string" &&
        Number.isInteger(l.nameIndex) &&
        Array.isArray(l.lines) &&
        l.lines.every((line) => typeof line === "string"),
    );
  if (!valid) {
    throw new Error("Invalid ignoreSpec in transfer plan");
  }
  const matcher = LayeredIgnoreMatcher.fromSpec(spec);
  return matcher.ruleCount > 0 ? matcher : null;
}

/**
 * Moves paths the source ignored out of the previous target tree (`oldRoot`) into the freshly
 * committed one (`newRoot`). Anything the source sent wins; internal BeamSync state is skipped.
 */
export async function carryOverIgnoredPaths(
  oldRoot: string,
  newRoot: string,
  matcher: LayeredIgnoreMatcher,
): Promise<{ moved: number; failures: Array<{ relPath: string; error: string }> }> {
  let moved = 0;
  const failures: Array<{ relPath: string; error: string }> = [];
  const describe = (err: unknown): string => (err instanceof Error ? err.message : String(err));

  async function walk(oldAbs: string, rel: string): Promise<void> {
    let dirents;
    try {
      dirents = await readdir(oldAbs, { withFileTypes: true });
    } catch (err) {
      failures.push({ relPath: rel || ".", error: describe(err) });
      return;
    }
    dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const d of dirents) {
      const childRel = rel ? `${rel}/${d.name}` : d.name;
      const isDirectory = d.isDirectory();
      if (matcher.isBuiltinIgnored(childRel, isDirectory)) continue;

      const oldChild = path.join(oldAbs, d.name);
      const newChild = path.join(newRoot, ...childRel.split("/"));
      const newStat = await lstat(newChild).catch(() => null);
      if (newStat) {
        // The source sent this path. Only a directory on both sides can still hold ignored paths.
        if (isDirectory && newStat.isDirectory()) await walk(oldChild, childRel);
        continue;
      }

      if (matcher.ignores(childRel, isDirectory)) {
        try {
          await mkdir(path.dirname(newChild), { recursive: true });
          await rename(oldChild, newChild);
          moved++;
        } catch (err) {
          failures.push({ relPath: childRel, error: describe(err) });
        }
        continue;
      }

      // A directory the source no longer has may still contain paths the source would ignore
      if (isDirectory) await walk(oldChild, childRel);
    }
  }

  await walk(oldRoot, "");
  return { moved, failures };
}

export class AtomicWorkspaceMaterializer {
  readonly targetDir: string;
  readonly stagingDir: string;
  readonly sessionId: string;
  private readonly manifest: TreeManifest;
  private readonly rootTreeDigest: string;
  private readonly existingBlobs: ReadonlyMap<string, BlobDiskSlice>;
  /** Built from the source's rules up front, so a malformed spec fails before anything moves. */
  private readonly carryOverMatcher: LayeredIgnoreMatcher | null;
  private readonly placements = new Map<string, BlobPlacement[]>();
  private readonly pendingBlobHashes = new Set<string>();
  private readonly hardlinkCanonicals = new Map<string, ManifestFileEntry>();
  private readonly hardlinkFollowers: Array<{
    canonicalRelPath: string;
    follower: ManifestFileEntry;
  }> = [];

  constructor(params: {
    targetDir: string;
    sessionId: string;
    manifest: TreeManifest;
    rootTreeDigest: string;
    existingBlobs: ReadonlyMap<string, BlobDiskSlice>;
    /** Ignore rules the source applied; matching paths in the old target tree are kept. */
    ignoreSpec?: IgnoreSpec;
    /** Mirror exactly: delete target paths the source ignored instead of keeping them. */
    deleteIgnored?: boolean;
  }) {
    this.carryOverMatcher =
      !params.deleteIgnored && params.ignoreSpec
        ? buildCarryOverMatcher(params.ignoreSpec)
        : null;
    this.targetDir = path.resolve(params.targetDir);
    this.sessionId = params.sessionId;
    const parentDir = path.dirname(this.targetDir);
    const baseName = path.basename(this.targetDir);
    this.stagingDir = path.join(
      parentDir,
      `.${baseName}.beamsync-staging-${params.sessionId.slice(0, 12)}`,
    );
    this.manifest = params.manifest;
    this.rootTreeDigest = params.rootTreeDigest;
    this.existingBlobs = params.existingBlobs;
  }

  async prepareStaging(): Promise<{
    missingBlobHashes: Set<string>;
  }> {
    await rm(this.stagingDir, { recursive: true, force: true });
    await mkdir(this.stagingDir, { recursive: true });

    // First pass: create directory structure & identify canonical hardlink group leaders
    for (const entry of this.manifest.entries) {
      const stagedPath = this.resolveStagedPath(entry.relPath);
      if (entry.kind === "dir") {
        await mkdir(stagedPath, { recursive: true });
        continue;
      }
      await mkdir(path.dirname(stagedPath), { recursive: true });

      if (entry.kind === "file" && entry.hardlinkGroupId) {
        if (!this.hardlinkCanonicals.has(entry.hardlinkGroupId)) {
          this.hardlinkCanonicals.set(entry.hardlinkGroupId, entry);
        } else {
          const canonical = this.hardlinkCanonicals.get(entry.hardlinkGroupId)!;
          this.hardlinkFollowers.push({
            canonicalRelPath: canonical.relPath,
            follower: entry,
          });
        }
      }
    }

    const followerPaths = new Set(
      this.hardlinkFollowers.map((f) => f.follower.relPath),
    );

    // Second pass: populate empty files, unchanged local blobs, and register missing placements
    for (const entry of this.manifest.entries) {
      if (entry.kind !== "file") continue;
      if (followerPaths.has(entry.relPath)) {
        // Will be hardlinked from canonical staged file during commit()
        continue;
      }

      const stagedPath = this.resolveStagedPath(entry.relPath);

      if (entry.size === 0) {
        await writeFile(stagedPath, new Uint8Array(0));
        continue;
      }

      if (entry.blobHash) {
        const localSlice = this.existingBlobs.get(entry.blobHash);
        if (localSlice) {
          await this.materializeFromLocalSlice(localSlice, stagedPath, entry);
        } else {
          this.addPlacement(entry.blobHash, {
            kind: "whole",
            stagedPath,
          });
          this.pendingBlobHashes.add(entry.blobHash);
        }
        continue;
      }

      if (entry.chunks && entry.chunks.length > 0) {
        // Pre-create & size multi-chunk file so concurrent pwrite operations never race on truncation
        const fh = await open(stagedPath, "w");
        await fh.close();
        await truncate(stagedPath, entry.size);

        for (const ch of entry.chunks) {
          const localSlice = this.existingBlobs.get(ch.hash);
          if (localSlice) {
            const buf = await readSliceFromDisk(localSlice);
            await writeSliceToStaged(stagedPath, buf, ch.offset);
          } else {
            this.addPlacement(ch.hash, {
              kind: "chunk",
              stagedPath,
              offset: ch.offset,
              length: ch.length,
            });
            this.pendingBlobHashes.add(ch.hash);
          }
        }
      }
    }

    return { missingBlobHashes: new Set(this.pendingBlobHashes) };
  }

  async applyIncomingBlobs(
    blobs: ReadonlyArray<{ hash: string; data: Uint8Array }>,
  ): Promise<void> {
    for (const blob of blobs) {
      const targets = this.placements.get(blob.hash);
      if (!targets || targets.length === 0) {
        this.pendingBlobHashes.delete(blob.hash);
        continue;
      }

      let firstWholePath: string | null = null;
      for (const target of targets) {
        if (target.kind === "whole") {
          if (!firstWholePath) {
            await writeFile(target.stagedPath, blob.data);
            firstWholePath = target.stagedPath;
          } else {
            await copyFile(firstWholePath, target.stagedPath);
          }
        } else {
          if (blob.data.length !== target.length) {
            throw new Error(
              `Chunk length mismatch for ${blob.hash}: expected ${target.length}, got ${blob.data.length}`,
            );
          }
          await writeSliceToStaged(target.stagedPath, blob.data, target.offset);
        }
      }

      this.placements.delete(blob.hash);
      this.pendingBlobHashes.delete(blob.hash);
    }
  }

  async commit(): Promise<CommitResult> {
    if (this.pendingBlobHashes.size > 0) {
      const sample = Array.from(this.pendingBlobHashes).slice(0, 3).join(", ");
      throw new Error(
        `Cannot commit workspace: ${this.pendingBlobHashes.size} required blobs still missing (${sample})`,
      );
    }

    // 1. Materialize intra-workspace hardlink followers
    for (const item of this.hardlinkFollowers) {
      const canonicalStaged = this.resolveStagedPath(item.canonicalRelPath);
      const followerStaged = this.resolveStagedPath(item.follower.relPath);
      await unlink(followerStaged).catch(() => {});
      await link(canonicalStaged, followerStaged);
    }

    // 2. Materialize relative symlinks
    let committedFiles = 0;
    for (const entry of this.manifest.entries) {
      const stagedPath = this.resolveStagedPath(entry.relPath);
      if (entry.kind === "symlink") {
        validateRelativeSymlinkTarget(entry.relPath, entry.linkTarget);
        await unlink(stagedPath).catch(() => {});
        await symlink(entry.linkTarget, stagedPath);
        committedFiles++;
      } else if (entry.kind === "file") {
        committedFiles++;
        await chmod(stagedPath, entry.mode & 0o777);
        const mtimeSec = entry.mtimeMs / 1000;
        await utimes(stagedPath, mtimeSec, mtimeSec).catch(() => {});
      }
    }

    // 3. Apply directory permissions bottom-up so restrictive modes don't block file writes
    const dirs = this.manifest.entries
      .filter((e) => e.kind === "dir")
      .sort((a, b) => b.relPath.length - a.relPath.length);
    for (const d of dirs) {
      const stagedPath = this.resolveStagedPath(d.relPath);
      await chmod(stagedPath, d.mode & 0o777).catch(() => {});
    }

    // 4. Write atomic commit marker inside .beamsync/ (ignored during digest scans)
    const metaDir = path.join(this.stagingDir, ".beamsync");
    await mkdir(metaDir, { recursive: true });
    await writeFile(
      path.join(metaDir, "commit-v1.json"),
      JSON.stringify(
        {
          schemaVersion: "beamsync-commit/v1",
          sessionId: this.sessionId,
          rootTreeDigest: this.rootTreeDigest,
          committedAt: new Date().toISOString(),
          entryCount: this.manifest.entries.length,
        },
        null,
        2,
      ),
      "utf8",
    );

    // 5. Atomic swap: targetDir -> backupDir, stagingDir -> targetDir, rm backupDir
    const parentDir = path.dirname(this.targetDir);
    const backupDir = path.join(
      parentDir,
      `.${path.basename(this.targetDir)}.beamsync-old-${this.sessionId.slice(0, 8)}`,
    );

    let hadExistingTarget = false;
    try {
      await stat(this.targetDir);
      hadExistingTarget = true;
    } catch {
      hadExistingTarget = false;
    }

    await rm(backupDir, { recursive: true, force: true });
    if (hadExistingTarget) {
      await rename(this.targetDir, backupDir);
    }

    try {
      await rename(this.stagingDir, this.targetDir);
    } catch (err) {
      // Roll back previous workspace if swap fails
      if (hadExistingTarget) {
        await rename(backupDir, this.targetDir).catch(() => {});
      }
      throw err;
    }

    // 6. Keep what the source deliberately skipped (dependency folders, local env files, ...)
    let preservedIgnoredPaths = 0;
    let preserveFailures: CommitResult["preserveFailures"] = [];
    if (hadExistingTarget && this.carryOverMatcher) {
      try {
        const carried = await carryOverIgnoredPaths(backupDir, this.targetDir, this.carryOverMatcher);
        preservedIgnoredPaths = carried.moved;
        preserveFailures = carried.failures;
      } catch (err) {
        // The new tree is already in place; never lose the previous one over a carry-over error
        preserveFailures = [{ relPath: ".", error: err instanceof Error ? err.message : String(err) }];
      }
    }

    if (hadExistingTarget && preserveFailures.length === 0) {
      await rm(backupDir, { recursive: true, force: true });
    }

    return {
      committedFiles,
      preservedIgnoredPaths,
      preserveFailures,
      retainedBackupDir: preserveFailures.length > 0 ? backupDir : undefined,
    };
  }

  async abort(): Promise<void> {
    await rm(this.stagingDir, { recursive: true, force: true }).catch(() => {});
  }

  private resolveStagedPath(relPath: string): string {
    const cleaned = relPath.split("/").join(path.sep);
    const resolved = path.resolve(this.stagingDir, cleaned);
    if (
      resolved !== this.stagingDir &&
      !resolved.startsWith(this.stagingDir + path.sep)
    ) {
      throw new Error(`Unsafe manifest path "${relPath}"`);
    }
    return resolved;
  }

  private addPlacement(hash: string, placement: BlobPlacement): void {
    const arr = this.placements.get(hash);
    if (arr) {
      arr.push(placement);
    } else {
      this.placements.set(hash, [placement]);
    }
  }

  private async materializeFromLocalSlice(
    slice: BlobDiskSlice,
    stagedPath: string,
    entry: ManifestFileEntry,
  ): Promise<void> {
    if (
      slice.offset === 0 &&
      slice.length === entry.size &&
      (slice.mode & 0o777) === (entry.mode & 0o777) &&
      !entry.hardlinkGroupId
    ) {
      try {
        await link(slice.absPath, stagedPath);
        return;
      } catch {
        // Cross-device or permission fallback: copy slice below
      }
    }
    const data = await readSliceFromDisk(slice);
    await writeFile(stagedPath, data);
  }
}

async function readSliceFromDisk(slice: BlobDiskSlice): Promise<Uint8Array> {
  const fh = await open(slice.absPath, "r");
  try {
    const buf = Buffer.allocUnsafe(slice.length);
    let totalRead = 0;
    while (totalRead < slice.length) {
      const { bytesRead } = await fh.read(
        buf,
        totalRead,
        slice.length - totalRead,
        slice.offset + totalRead,
      );
      if (bytesRead === 0) break;
      totalRead += bytesRead;
    }
    return new Uint8Array(buf.buffer, buf.byteOffset, totalRead);
  } finally {
    await fh.close();
  }
}

async function writeSliceToStaged(
  stagedPath: string,
  data: Uint8Array,
  offset: number,
): Promise<void> {
  const fh = await open(stagedPath, "r+");
  try {
    let written = 0;
    while (written < data.length) {
      const { bytesWritten } = await fh.write(
        data,
        written,
        data.length - written,
        offset + written,
      );
      written += bytesWritten;
    }
  } finally {
    await fh.close();
  }
}
