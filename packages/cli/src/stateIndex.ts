import {
  lstat,
  mkdir,
  open,
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
  FastCdcStreamChunker,
  LayeredIgnoreMatcher,
  utf8Bytes,
  validateRelativeSymlinkTarget,
  type ContentChunkRef,
  type FastCdcOptions,
  type FileChunkRef,
  type IgnoreDecision,
  type IgnoreSpec,
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

/** The ignore file that is always honoured, in every directory of the workspace. */
export const DEFAULT_IGNORE_FILE_NAME = ".beamsyncignore";

export interface IgnoreOptions {
  /**
   * Extra ignore file names to honour in every directory (e.g. `.raftmigrationignore`).
   * Later names take precedence over earlier ones; `.beamsyncignore` always wins.
   */
  ignoreFileNames?: string[];
  /** Also honour `.gitignore` files, with lower precedence than every other ignore file. */
  respectGitignore?: boolean;
  /** Explicit gitignore-style patterns anchored at the workspace root. Highest precedence. */
  extraIgnoreRules?: string[];
  /** Rules files outside the workspace, anchored at the workspace root. Lowest precedence. */
  ignoreFromFiles?: string[];
}

export interface ScanWorkspaceOptions extends IgnoreOptions {
  cacheDir?: string;
  smallFileThresholdBytes?: number;
  cdcOptions?: FastCdcOptions;
  /** Stops the walk before the next entry; the scan then rejects with `SCAN_ABORTED`. */
  signal?: AbortSignal;
  /** How much of a large file is read per call while it is chunked (default 4 MiB). */
  readBlockBytes?: number;
}

export const DEFAULT_SCAN_READ_BLOCK_BYTES = 4 * 1024 * 1024;

/**
 * Splits a file into content-defined chunks while reading it block by block, so memory use
 * does not depend on the file size. Reads up to the end of the file as it is at that moment.
 */
export async function chunkFileStreaming(
  absPath: string,
  options: {
    cdcOptions?: FastCdcOptions;
    readBlockBytes?: number;
    signal?: AbortSignal;
  } = {},
): Promise<ContentChunkRef[]> {
  const blockBytes = Math.max(1, options.readBlockBytes ?? DEFAULT_SCAN_READ_BLOCK_BYTES);
  const chunker = new FastCdcStreamChunker(options.cdcOptions);
  const chunks: ContentChunkRef[] = [];
  const block = Buffer.allocUnsafe(blockBytes);
  const fh = await open(absPath, "r");
  try {
    let position = 0;
    for (;;) {
      if (options.signal?.aborted) {
        throw new Error("SCAN_ABORTED: Workspace scan was cancelled");
      }
      const { bytesRead } = await fh.read(block, 0, blockBytes, position);
      if (bytesRead === 0) break;
      position += bytesRead;
      for (const c of chunker.push(block.subarray(0, bytesRead))) chunks.push(c);
    }
    for (const c of chunker.finish()) chunks.push(c);
  } finally {
    await fh.close();
  }
  return chunks;
}

export interface ScanWorkspaceResult {
  rootPath: string;
  manifest: TreeManifest;
  rootTreeDigest: string;
  blobSlices: Map<string, BlobDiskSlice>;
  cachedFileHits: number;
  hashedFiles: number;
  /** Effective ignore rules, in a form the receiver can evaluate on its own tree. */
  ignoreSpec: IgnoreSpec;
  /** Entries skipped by a user rule (an ignored directory counts once). */
  ignoredPathCount: number;
  /** Workspace-relative paths of the ignore files that contributed rules. */
  ignoreFilesLoaded: string[];
}

/** Ordered list of ignore file names: lowest precedence first. */
export function resolveIgnoreFileNames(options: IgnoreOptions = {}): string[] {
  const names: string[] = [];
  const add = (name: string): void => {
    const trimmed = name.trim();
    if (!trimmed) return;
    if (trimmed === "." || trimmed === ".." || /[\\/]/.test(trimmed)) {
      throw new Error(
        `Invalid ignore file name "${name}": expected a plain file name such as ".gitignore". ` +
          `Use --ignore-from <path> for a rules file outside the workspace.`,
      );
    }
    if (trimmed !== DEFAULT_IGNORE_FILE_NAME && !names.includes(trimmed)) names.push(trimmed);
  };
  if (options.respectGitignore) add(".gitignore");
  for (const name of options.ignoreFileNames ?? []) add(name);
  names.push(DEFAULT_IGNORE_FILE_NAME);
  return names;
}

function splitRuleLines(content: string): string[] {
  return content.replace(/^\uFEFF/, "").split(/\r?\n/);
}

interface IgnoreContext {
  matcher: LayeredIgnoreMatcher;
  fileNames: string[];
  filesLoaded: string[];
}

async function createIgnoreContext(options: IgnoreOptions): Promise<IgnoreContext> {
  const matcher = new LayeredIgnoreMatcher();
  for (const fromPath of options.ignoreFromFiles ?? []) {
    let content: string;
    try {
      content = await readFile(fromPath, "utf8");
    } catch (err) {
      throw new Error(
        `Cannot read ignore rules file "${fromPath}": ${err instanceof Error ? err.message : err}`,
      );
    }
    matcher.addLayer({
      kind: "from",
      source: path.basename(fromPath),
      baseDir: "",
      nameIndex: 0,
      lines: splitRuleLines(content),
    });
  }
  if (options.extraIgnoreRules?.length) {
    matcher.addLayer({
      kind: "explicit",
      source: "--ignore",
      baseDir: "",
      nameIndex: 0,
      lines: options.extraIgnoreRules,
    });
  }
  return { matcher, fileNames: resolveIgnoreFileNames(options), filesLoaded: [] };
}

/** Loads the ignore files that sit directly in one directory, before its entries are tested. */
async function loadDirectoryIgnoreFiles(
  ctx: IgnoreContext,
  dirAbs: string,
  dirRel: string,
  dirents: ReadonlyArray<{ name: string; isFile(): boolean }>,
): Promise<void> {
  for (let nameIndex = 0; nameIndex < ctx.fileNames.length; nameIndex++) {
    const name = ctx.fileNames[nameIndex];
    // Only regular files: a symlinked ignore file could pull in rules from outside the workspace
    if (!dirents.some((d) => d.name === name && d.isFile())) continue;
    const source = dirRel ? `${dirRel}/${name}` : name;
    let content: string;
    try {
      content = await readFile(path.join(dirAbs, name), "utf8");
    } catch (err) {
      throw new Error(
        `Cannot read ignore file "${source}": ${err instanceof Error ? err.message : err}`,
      );
    }
    const added = ctx.matcher.addLayer({
      kind: "file",
      source,
      baseDir: dirRel,
      nameIndex,
      lines: splitRuleLines(content),
    });
    if (added > 0) ctx.filesLoaded.push(source);
  }
}

export interface IgnoredPathInfo {
  relPath: string;
  isDirectory: boolean;
  /** Rule that matched (absent for built-in internal paths). */
  pattern?: string;
  /** Ignore file (workspace-relative), "--ignore", a rules file name, or "built-in". */
  source?: string;
}

/**
 * Walks a workspace without hashing anything and reports what a send would skip.
 * Ignored directories are reported once and not entered.
 */
export async function listIgnoredPaths(
  dirPath: string,
  options: IgnoreOptions = {},
): Promise<{ ignored: IgnoredPathInfo[]; includedEntries: number; ignoreFilesLoaded: string[] }> {
  const resolvedRoot = await realpath(dirPath);
  const ctx = await createIgnoreContext(options);
  const ignored: IgnoredPathInfo[] = [];
  let includedEntries = 0;

  async function walk(currentAbs: string, currentRel: string): Promise<void> {
    const dirents = await readdir(currentAbs, { withFileTypes: true });
    dirents.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    await loadDirectoryIgnoreFiles(ctx, currentAbs, currentRel, dirents);
    for (const d of dirents) {
      const childRel = currentRel ? `${currentRel}/${d.name}` : d.name;
      const isDirectory = d.isDirectory();
      const decision: IgnoreDecision = ctx.matcher.explain(childRel, isDirectory);
      if (decision.ignored) {
        ignored.push({
          relPath: childRel,
          isDirectory,
          pattern: decision.pattern,
          source: decision.source,
        });
        continue;
      }
      includedEntries++;
      if (isDirectory) await walk(path.join(currentAbs, d.name), childRel);
    }
  }

  await walk(resolvedRoot, "");
  return { ignored, includedEntries, ignoreFilesLoaded: ctx.filesLoaded };
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

  const ignoreCtx = await createIgnoreContext(options);
  const matcher = ignoreCtx.matcher;
  let ignoredPathCount = 0;

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

    await loadDirectoryIgnoreFiles(ignoreCtx, currentAbs, currentRel, dirents);

    let hasIncludedChildren = false;
    for (const d of dirents) {
      const childRel = currentRel ? `${currentRel}/${d.name}` : d.name;
      const decision = matcher.explain(childRel, d.isDirectory());
      if (decision.ignored) {
        if (!decision.builtin) ignoredPathCount++;
        continue;
      }
      if (options.signal?.aborted) throw new Error("SCAN_ABORTED: Workspace scan was cancelled");
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
        try {
          validateRelativeSymlinkTarget(childRel, linkTarget);
        } catch (err) {
          throw new Error(
            `${err instanceof Error ? err.message : err}. ` +
              `Exclude it with an ignore rule (--ignore "/${childRel}" or an ignore file) to send the rest.`,
          );
        }
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

        if (size <= smallThreshold) {
          const buf = await readFile(childAbs);
          const blobHash = blake3Hex(new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength));
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
          // Never held in memory as a whole: a workspace can contain files of many GiB
          const cdcChunks = await chunkFileStreaming(childAbs, {
            cdcOptions: options.cdcOptions,
            readBlockBytes: options.readBlockBytes,
            signal: options.signal,
          });
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
    ignoreSpec: matcher.toSpec(),
    ignoredPathCount,
    ignoreFilesLoaded: ignoreCtx.filesLoaded,
  };
}
