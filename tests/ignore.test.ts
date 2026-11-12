import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { execFileSync } from "node:child_process";
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readdir,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { LayeredIgnoreMatcher, compileIgnorePattern } from "@beamsync/protocol";
import { startBeamSyncServer, type RunningBeamSyncServer } from "@beamsync/server";
import {
  AtomicWorkspaceMaterializer,
  carryOverIgnoredPaths,
  ignoreOptionsFromArgs,
  listIgnoredPaths,
  parseArgs,
  receiveDirectory,
  resolveIgnoreFileNames,
  scanWorkspace,
  sendDirectory,
  type IgnoreOptions,
  type ReceiveDirectoryOptions,
  type SendDirectoryOptions,
} from "@beamsync/cli";

async function writeTree(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, ...rel.split("/"));
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content, "utf8");
  }
}

async function exists(p: string): Promise<boolean> {
  return lstat(p).then(
    () => true,
    () => false,
  );
}

/** Files and symlinks a send would transfer, as sorted workspace-relative paths. */
async function sentPaths(root: string, cacheDir: string, options: IgnoreOptions = {}): Promise<string[]> {
  const scan = await scanWorkspace(root, { cacheDir, ...options });
  return scan.manifest.entries
    .filter((e) => e.kind !== "dir")
    .map((e) => e.relPath)
    .sort();
}

describe("ignore rules", () => {
  let tmpRoot: string;
  let cacheDir: string;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-ignore-"));
    cacheDir = path.join(tmpRoot, "cache");
  });

  afterEach(async () => {
    await rm(tmpRoot, { recursive: true, force: true });
  });

  it("matches what git itself ignores for a wide range of .gitignore patterns", async () => {
    const repo = path.join(tmpRoot, "repo");
    const rootRules = [
      "# comment line",
      "",
      "*.log",
      "!important.log",
      "/build",
      "dist/",
      "docs/**/*.pdf",
      "**/cache",
      "logs/**",
      "a/**/z",
      "foo[0-9].txt",
      "bar[!a-c].txt",
      "\\#hash",
      "\\!bang",
      "trail\\ ",
      "*.tmp   ",
      "node_modules/",
      "!node_modules/keep.txt",
      "/only-root.txt",
      "sub/dir-only-here/",
      "*.[oa]",
      "temp?",
      "**/deep/**/x.txt",
      "[[:digit:]]file",
      "*.env",
      "!example.env",
      "mid*dle",
      "/anch/*.c",
      "!/anch/keep.c",
      "vendor/*",
      "!vendor/ours/",
      "quest?on",
      "**/many/**/**/leaf",
      "star**star",
    ];
    const pkgRules = ["!*.log", "/local.txt", "gen/", "*.md", "!README.md"];

    const paths = [
      "a.log", "important.log", "deep1/b.log", "deep1/important.log",
      "build/out.js", "sub/build/out.js",
      "dist/x.js", "sub/dist/y.js", "distfile", "sub2/dist",
      "docs/a.pdf", "docs/x/y/b.pdf", "docs/x/readme.md", "other/c.pdf",
      "cache/f", "x/y/cache/g", "x/cache",
      "logs/a.txt", "logs/sub/b.txt", "x/logs/c.txt",
      "a/z", "a/b/z", "a/b/c/z", "a/b/zz", "q/a/z",
      "foo1.txt", "fooa.txt", "foo12.txt",
      "bard.txt", "bara.txt",
      "#hash", "!bang", "trail ", "trail",
      "x.tmp", "x.tmpl",
      "node_modules/keep.txt", "node_modules/pkg/index.js", "pkg/node_modules/z.js",
      "only-root.txt", "sub/only-root.txt",
      "sub/dir-only-here/f", "other/sub/dir-only-here/f",
      "lib.o", "lib.a", "lib.so",
      "temp1", "temp", "temp12",
      "p/deep/x.txt", "p/deep/q/r/x.txt", "deep/x.txt", "p/deepx/x.txt",
      "1file", "afile",
      "prod.env", "example.env", ".env", "conf/.env",
      "middle", "mid-xx-dle", "midle",
      "anch/a.c", "anch/keep.c", "anch/sub/b.c", "other/anch/c.c",
      "vendor/theirs/a.js", "vendor/ours/b.js", "vendor/top.js",
      "question", "questXon", "queston",
      "many/leaf", "many/a/b/leaf", "z/many/q/leaf", "manyleaf",
      "starstar", "star-mid-star", "star/x/star",
      "pkg/debug.log", "pkg/local.txt", "pkg/sub/local.txt", "pkg/gen/a.js",
      "pkg/sub/gen/b.js", "pkg/notes.md", "pkg/README.md", "pkg/sub/deep.log",
      "plain/src/index.ts",
    ];
    const files: Record<string, string> = {
      ".gitignore": rootRules.join("\n") + "\n",
      "pkg/.gitignore": pkgRules.join("\r\n") + "\r\n",
    };
    for (const p of paths) files[p] = `content of ${p}\n`;
    await writeTree(repo, files);
    // "dist/" is directory-only, so a symlink called dist-link is kept; "*.log" hits a symlink
    await symlink("dist", path.join(repo, "dist-link"));
    await symlink("plain/src/index.ts", path.join(repo, "link.log"));

    const gitEnv = {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
      HOME: path.join(tmpRoot, "home"),
      XDG_CONFIG_HOME: path.join(tmpRoot, "home", "xdg"),
    };
    execFileSync("git", ["init", "-q", repo], { env: gitEnv });
    const gitKept = execFileSync("git", ["ls-files", "--others", "--exclude-standard", "-z"], {
      cwd: repo,
      env: gitEnv,
      encoding: "utf8",
    })
      .split("\0")
      .filter(Boolean)
      .sort();

    const ours = (await sentPaths(repo, cacheDir, { respectGitignore: true })).filter(
      (p) => !p.startsWith(".git/"),
    );

    expect(gitKept.length).toBeGreaterThan(30);
    expect(ours).toEqual(gitKept);

    // The dry listing agrees with the scan
    const listing = await listIgnoredPaths(repo, { respectGitignore: true });
    const listed = listing.ignored.map((i) => i.relPath);
    expect(listed).toContain("node_modules");
    expect(listed).toContain("pkg/gen");
    expect(listed.some((p) => ours.includes(p))).toBe(false);
    expect(listing.ignored.find((i) => i.relPath === "pkg/local.txt")).toMatchObject({
      pattern: "/local.txt",
      source: "pkg/.gitignore",
    });
    expect(listing.ignoreFilesLoaded.sort()).toEqual([".gitignore", "pkg/.gitignore"]);
  });

  it("agrees with git on randomly generated trees and nested .gitignore files", async () => {
    let seed = 20261112;
    const rnd = (): number => {
      seed = (seed * 1103515245 + 12345) >>> 0;
      return seed / 2 ** 32;
    };
    const pick = <T,>(arr: T[]): T => arr[Math.floor(rnd() * arr.length)];
    const names = ["a", "b", "ab", "abc", "a.b", "b.c", "x1", "x2", "foo", "bar", "a b", "#c", "!d", "[e]", "a-b", "A"];
    const atoms = [
      "a", "b", "ab", "*", "?", "a*", "*b", "*.b", "*.c", "x[0-9]", "x[!1]", "[ab]", "[a-c]*", "**", "foo", "bar",
      "a?c", "\\#c", "\\!d", "\\[e\\]", "a\\ b", "[[:upper:]]", "a-b", "*-*", "[a\\-z]", "[]a]", "**b", "a**",
    ];
    const randPattern = (): string => {
      let p = Array.from({ length: 1 + Math.floor(rnd() * 3) }, () => pick(atoms)).join("/");
      if (rnd() < 0.25) p = `/${p}`;
      if (rnd() < 0.3) p += "/";
      if (rnd() < 0.25) p = `!${p}`;
      if (rnd() < 0.1) p += "  ";
      return p;
    };
    const gitEnv = {
      ...process.env,
      GIT_CONFIG_GLOBAL: "/dev/null",
      GIT_CONFIG_SYSTEM: "/dev/null",
      HOME: path.join(tmpRoot, "home"),
      XDG_CONFIG_HOME: path.join(tmpRoot, "home", "xdg"),
    };

    const mismatches: unknown[] = [];
    let written = 0;
    let kept = 0;
    for (let trial = 0; trial < 60; trial++) {
      const repo = path.join(tmpRoot, `fuzz-${trial}`);
      const files: string[] = [];
      const dirs = new Set<string>();
      const candidates = new Set<string>();
      for (let i = 0; i < 40; i++) {
        candidates.add(Array.from({ length: 1 + Math.floor(rnd() * 4) }, () => pick(names)).join("/"));
      }
      for (const candidate of [...candidates].sort()) {
        const parts = candidate.split("/");
        const parents = parts.slice(1).map((_, i) => parts.slice(0, i + 1).join("/"));
        if (dirs.has(candidate) || parents.some((p) => files.includes(p))) continue;
        for (const p of parents) dirs.add(p);
        files.push(candidate);
      }
      const tree: Record<string, string> = {
        ".gitignore": Array.from({ length: 1 + Math.floor(rnd() * 5) }, randPattern).join("\n") + "\n",
      };
      for (const f of files) tree[f] = "x";
      for (const d of dirs) {
        if (rnd() < 0.25) {
          tree[`${d}/.gitignore`] = Array.from({ length: 1 + Math.floor(rnd() * 3) }, randPattern).join("\n") + "\n";
        }
      }
      await writeTree(repo, tree);

      execFileSync("git", ["init", "-q", repo], { env: gitEnv });
      const gitKept = execFileSync("git", ["ls-files", "--others", "--exclude-standard", "-z"], {
        cwd: repo,
        env: gitEnv,
        encoding: "utf8",
      })
        .split("\0")
        .filter(Boolean)
        .sort();
      const ours = (await sentPaths(repo, cacheDir, { respectGitignore: true })).filter(
        (p) => !p.startsWith(".git/"),
      );
      written += files.length;
      kept += gitKept.filter((p) => !p.endsWith(".gitignore")).length;
      if (JSON.stringify(ours) !== JSON.stringify(gitKept)) {
        mismatches.push({
          trial,
          rules: Object.fromEntries(Object.entries(tree).filter(([k]) => k.endsWith(".gitignore"))),
          onlyGit: gitKept.filter((p) => !ours.includes(p)),
          onlyOurs: ours.filter((p) => !gitKept.includes(p)),
        });
      }
      await rm(repo, { recursive: true, force: true });
    }

    expect(mismatches).toEqual([]);
    // Guard against a vacuous run: a real share of the files must have been ignored
    expect(written).toBeGreaterThan(1000);
    expect(kept).toBeGreaterThan(written * 0.3);
    expect(kept).toBeLessThan(written * 0.9);
  }, 120_000);

  it("leaves .gitignore alone unless asked, and always reads nested .beamsyncignore files", async () => {
    const root = path.join(tmpRoot, "ws");
    await writeTree(root, {
      ".gitignore": "node_modules/\n.env\n",
      ".beamsyncignore": "*.tmp\n",
      "svc/.beamsyncignore": "/out/\n",
      ".env": "SECRET=1\n",
      "node_modules/a/index.js": "a\n",
      "scratch.tmp": "x\n",
      "svc/out/bundle.js": "b\n",
      "svc/src/out/keep.js": "k\n",
      "svc/main.ts": "m\n",
    });

    const byDefault = await sentPaths(root, cacheDir);
    expect(byDefault).toEqual([
      ".beamsyncignore",
      ".env",
      ".gitignore",
      "node_modules/a/index.js",
      "svc/.beamsyncignore",
      "svc/main.ts",
      "svc/src/out/keep.js",
    ]);

    const withGit = await sentPaths(root, cacheDir, { respectGitignore: true });
    expect(withGit).toEqual([
      ".beamsyncignore",
      ".gitignore",
      "svc/.beamsyncignore",
      "svc/main.ts",
      "svc/src/out/keep.js",
    ]);
  });

  it("honours custom ignore file names with a clear precedence order", async () => {
    const root = path.join(tmpRoot, "ws");
    await writeTree(root, {
      // Lowest: .gitignore (nested one would normally beat the root one)
      ".gitignore": "*.env\nnode_modules/\n",
      "app/.gitignore": "generated/\n*.snap\n",
      // A root custom file overrides a nested .gitignore
      ".raftmigrationignore": "!*.env\n!generated/\n*.bak\n/app/tmp/\n",
      // .beamsyncignore beats every other ignore file
      ".beamsyncignore": "!keep.bak\n",
      ".env": "A=1\n",
      "app/local.env": "B=2\n",
      "app/generated/api.ts": "g\n",
      "app/ui.snap": "s\n",
      "app/tmp/x": "x\n",
      "app/src/tmp/y": "y\n",
      "node_modules/m/i.js": "i\n",
      "old.bak": "o\n",
      "keep.bak": "k\n",
      "notes.txt": "n\n",
      "big.iso": "iso\n",
    });
    const extRules = path.join(tmpRoot, "external-rules.txt");
    await writeFile(extRules, "notes.txt\n*.iso\n!.env\n", "utf8");

    const base: IgnoreOptions = {
      respectGitignore: true,
      ignoreFileNames: [".raftmigrationignore"],
    };
    expect(await sentPaths(root, cacheDir, base)).toEqual([
      ".beamsyncignore",
      ".env",
      ".gitignore",
      ".raftmigrationignore",
      "app/.gitignore",
      "app/generated/api.ts",
      "app/local.env",
      "app/src/tmp/y",
      "big.iso",
      "keep.bak",
      "notes.txt",
    ]);

    // --ignore-from is the lowest layer, --ignore the highest
    const layered = await sentPaths(root, cacheDir, {
      ...base,
      ignoreFromFiles: [extRules],
      extraIgnoreRules: ["/app/generated/", "!old.bak", "!big.iso"],
    });
    expect(layered).toEqual([
      ".beamsyncignore",
      ".env",
      ".gitignore",
      ".raftmigrationignore",
      "app/.gitignore",
      "app/local.env",
      "app/src/tmp/y",
      "big.iso",
      "keep.bak",
      "old.bak",
    ]);

    // Without the flag the custom file is just a file
    const plain = await sentPaths(root, cacheDir);
    expect(plain).toContain("old.bak");
    expect(plain).toContain("app/tmp/x");

    const scan = await scanWorkspace(root, { cacheDir, ...base });
    expect(scan.ignoreFilesLoaded.sort()).toEqual([
      ".beamsyncignore",
      ".gitignore",
      ".raftmigrationignore",
      "app/.gitignore",
    ]);
    expect(scan.ignoredPathCount).toBe(4); // app/tmp, app/ui.snap, node_modules, old.bak
  });

  it("never lets a rule re-include internal BeamSync state, and rejects bad ignore file names", async () => {
    const root = path.join(tmpRoot, "ws");
    await writeTree(root, {
      ".beamsyncignore": "!.beamsync/\n!.beamsync-*\n",
      ".beamsync/commit-v1.json": "{}\n",
      ".beamsync-staging-abc/partial": "p\n",
      "a.txt": "a\n",
    });
    expect(await sentPaths(root, cacheDir, { extraIgnoreRules: ["!.beamsync/"] })).toEqual([
      ".beamsyncignore",
      "a.txt",
    ]);

    expect(resolveIgnoreFileNames({ respectGitignore: true, ignoreFileNames: [".x", ".gitignore", ".x"] })).toEqual([
      ".gitignore",
      ".x",
      ".beamsyncignore",
    ]);
    expect(() => resolveIgnoreFileNames({ ignoreFileNames: ["../outside"] })).toThrow(/plain file name/);
    await expect(scanWorkspace(root, { cacheDir, ignoreFromFiles: [path.join(tmpRoot, "nope")] })).rejects.toThrow(
      /Cannot read ignore rules file/,
    );
  });

  it("does not follow a symlinked ignore file", async () => {
    const root = path.join(tmpRoot, "ws");
    await writeTree(root, { "rules/real": "*.txt\n", "a.txt": "a\n" });
    await symlink("rules/real", path.join(root, ".beamsyncignore"));
    expect(await sentPaths(root, cacheDir)).toEqual([".beamsyncignore", "a.txt", "rules/real"]);
  });

  it("tells the user how to skip a symlink that cannot be transferred", async () => {
    const root = path.join(tmpRoot, "ws");
    await writeTree(root, { "venv/lib/x.py": "x\n" });
    await symlink("/usr/bin/python3", path.join(root, "venv", "python"));
    await expect(scanWorkspace(root, { cacheDir })).rejects.toThrow(/--ignore "\/venv\/python"/);
    expect(await sentPaths(root, cacheDir, { extraIgnoreRules: ["/venv/python"] })).toEqual(["venv/lib/x.py"]);
  });

  it("compiles patterns without pathological regexes and skips unusable ones", () => {
    expect(compileIgnorePattern("# comment")).toBeNull();
    expect(compileIgnorePattern("   ")).toBeNull();
    expect(compileIgnorePattern("/")).toBeNull();
    expect(compileIgnorePattern("[z-a]")).toBeNull();
    const m = new LayeredIgnoreMatcher([
      { kind: "explicit", source: "t", baseDir: "", nameIndex: 0, lines: ["**/**/**/**/**/**/**/**/needle"] },
    ]);
    const hay = `${"d/".repeat(400)}haystack`;
    const started = Date.now();
    expect(m.ignores(hay, false)).toBe(false);
    expect(m.ignores(`${"d/".repeat(400)}needle`, false)).toBe(true);
    expect(Date.now() - started).toBeLessThan(500);
  });

  it("parses repeated flags, --flag=value and boolean flags before positionals", () => {
    const { positional, flags, multi } = parseArgs([
      "send",
      "--respect-gitignore",
      "./workspace",
      "--ignore",
      "*.log",
      "--ignore=!keep.log",
      "--ignore-file",
      ".raftmigrationignore,.dockerignore",
      "--ignore-file",
      ".npmignore",
      "--ignore-from",
      "/etc/rules",
      "--max-mbps",
      "20",
    ]);
    expect(positional).toEqual(["send", "./workspace"]);
    expect(flags["max-mbps"]).toBe("20");
    const opts = ignoreOptionsFromArgs(flags, multi, { BEAMSYNC_IGNORE_FILES: ".envignore, .raftmigrationignore" });
    expect(opts).toEqual({
      ignoreFileNames: [".envignore", ".raftmigrationignore", ".raftmigrationignore", ".dockerignore", ".npmignore"],
      respectGitignore: true,
      extraIgnoreRules: ["*.log", "!keep.log"],
      ignoreFromFiles: ["/etc/rules"],
    });
    expect(resolveIgnoreFileNames(opts)).toEqual([
      ".gitignore",
      ".envignore",
      ".raftmigrationignore",
      ".dockerignore",
      ".npmignore",
      ".beamsyncignore",
    ]);
    expect(() => ignoreOptionsFromArgs({ ignore: true }, {}, {})).toThrow(/--ignore requires a value/);
  });
});

describe("ignored paths on the receiving side", () => {
  let tmpRoot: string;
  let server: RunningBeamSyncServer;

  beforeEach(async () => {
    tmpRoot = await mkdtemp(path.join(os.tmpdir(), "beamsync-ignore-e2e-"));
    server = await startBeamSyncServer({
      port: 0,
      host: "127.0.0.1",
      stunPort: 0,
      publicStunHost: "127.0.0.1",
      dataDir: path.join(tmpRoot, "server-data"),
    });
  });

  afterEach(async () => {
    await server.close();
    await rm(tmpRoot, { recursive: true, force: true });
  });

  async function transfer(
    sourceDir: string,
    targetDir: string,
    sendOpts: Partial<SendDirectoryOptions> = {},
    receiveOpts: Partial<ReceiveDirectoryOptions> = {},
  ) {
    let resolveCode!: (code: string) => void;
    const codePromise = new Promise<string>((r) => {
      resolveCode = r;
    });
    const sendPromise = sendDirectory({
      serverUrl: server.httpUrl,
      sourceDir,
      cacheDir: path.join(tmpRoot, "cache-src"),
      hostIdOverride: "ignore-test-host",
      onPairingCode: (code) => resolveCode(code),
      ...sendOpts,
    });
    sendPromise.catch(() => {});
    const code = await Promise.race([codePromise, sendPromise.then(() => "")]);
    const received = await receiveDirectory({
      serverUrl: server.httpUrl,
      targetDir,
      pairingCode: code,
      cacheDir: path.join(tmpRoot, "cache-dst"),
      hostIdOverride: "ignore-test-host",
      ...receiveOpts,
    });
    return { sent: await sendPromise, received };
  }

  async function seed(sourceDir: string, targetDir: string): Promise<void> {
    await writeTree(sourceDir, {
      ".raftmigrationignore": "node_modules/\n.env\n*.log\n/build/\n",
      ".gitignore": "coverage/\n",
      "src/index.ts": "export const v = 2;\n",
      "src/new.ts": "export const n = 1;\n",
      "coverage/lcov.info": "source coverage is sent: .gitignore is not honoured here\n",
      "node_modules/left-pad/index.js": "SOURCE_NODE_MODULES\n",
      ".env": "SOURCE_SECRET=1\n",
      "debug.log": "source log\n",
      "build/out.js": "source build\n",
    });
    await writeTree(targetDir, {
      "src/index.ts": "export const v = 1;\n",
      "src/stale.ts": "removed on the source\n",
      "node_modules/react/index.js": "TARGET_NODE_MODULES\n",
      ".env": "TARGET_SECRET=1\n",
      "src/trace.log": "target log next to synced files\n",
      "gone/deeper/session.log": "ignored file under a directory the source does not have\n",
      "gone/deeper/plain.txt": "not ignored, source does not have it\n",
      "build": "on the target this is a file, so the directory-only rule does not cover it\n",
      ".beamsync/commit-v1.json": "{\"old\":true}\n",
    });
  }

  it("keeps the target's own copies of paths the sender ignored, and still removes stale paths", async () => {
    const sourceDir = path.join(tmpRoot, "source");
    const targetDir = path.join(tmpRoot, "target");
    await seed(sourceDir, targetDir);

    const { sent, received } = await transfer(sourceDir, targetDir, {
      ignoreFileNames: [".raftmigrationignore"],
    });

    expect(sent.ignoredPaths).toBe(4); // .env, build, debug.log, node_modules
    expect(sent.ignoreFilesLoaded).toEqual([".raftmigrationignore"]);
    expect(received.rootTreeDigest).toBe(sent.rootTreeDigest);

    // Sent content replaced the target's
    expect(await readFile(path.join(targetDir, "src/index.ts"), "utf8")).toBe("export const v = 2;\n");
    expect(await exists(path.join(targetDir, "src/new.ts"))).toBe(true);
    expect(await exists(path.join(targetDir, "coverage/lcov.info"))).toBe(true);
    // Ignored on the source: never transferred
    expect(await exists(path.join(targetDir, "node_modules/left-pad"))).toBe(false);
    expect(await exists(path.join(targetDir, "debug.log"))).toBe(false);
    // Ignored on the source: the target keeps what it had
    expect(await readFile(path.join(targetDir, "node_modules/react/index.js"), "utf8")).toBe("TARGET_NODE_MODULES\n");
    expect(await readFile(path.join(targetDir, ".env"), "utf8")).toBe("TARGET_SECRET=1\n");
    expect(await exists(path.join(targetDir, "src/trace.log"))).toBe(true);
    expect(await exists(path.join(targetDir, "gone/deeper/session.log"))).toBe(true);
    // Not ignored and absent on the source: removed
    expect(await exists(path.join(targetDir, "src/stale.ts"))).toBe(false);
    expect(await exists(path.join(targetDir, "gone/deeper/plain.txt"))).toBe(false);
    expect(await exists(path.join(targetDir, "build"))).toBe(false);

    expect(received.preservedIgnoredPaths).toBe(4); // .env, node_modules, src/trace.log, gone/deeper/session.log
    expect(received.preserveFailures).toEqual([]);
    expect(received.retainedBackupDir).toBeUndefined();
    // Fresh commit marker, and no leftover backup or staging directories next to the target
    expect(await readFile(path.join(targetDir, ".beamsync/commit-v1.json"), "utf8")).toContain(sent.rootTreeDigest);
    expect((await readdir(tmpRoot)).filter((n) => n.includes("beamsync-old") || n.includes("beamsync-staging"))).toEqual([]);

    // The target tree minus what the sender ignores is exactly the source tree
    const targetAsSource = await scanWorkspace(targetDir, {
      cacheDir: path.join(tmpRoot, "cache-verify"),
      ignoreFileNames: [".raftmigrationignore"],
      extraIgnoreRules: ["/gone/"],
    });
    expect(targetAsSource.rootTreeDigest).toBe(sent.rootTreeDigest);
  });

  it("mirrors exactly with deleteIgnored", async () => {
    const sourceDir = path.join(tmpRoot, "source");
    const targetDir = path.join(tmpRoot, "target");
    await seed(sourceDir, targetDir);

    const { sent, received } = await transfer(
      sourceDir,
      targetDir,
      { ignoreFileNames: [".raftmigrationignore"] },
      { deleteIgnored: true },
    );

    expect(received.preservedIgnoredPaths).toBe(0);
    expect(await exists(path.join(targetDir, "node_modules"))).toBe(false);
    expect(await exists(path.join(targetDir, ".env"))).toBe(false);
    expect(await exists(path.join(targetDir, "gone"))).toBe(false);
    const mirrored = await scanWorkspace(targetDir, { cacheDir: path.join(tmpRoot, "cache-verify") });
    expect(mirrored.rootTreeDigest).toBe(sent.rootTreeDigest);
  });

  it("deletes nothing extra and preserves nothing when the sender has no ignore rules", async () => {
    const sourceDir = path.join(tmpRoot, "source");
    const targetDir = path.join(tmpRoot, "target");
    await writeTree(sourceDir, { "a.txt": "a\n" });
    await writeTree(targetDir, { "node_modules/x.js": "x\n", "a.txt": "old\n" });
    const { sent, received } = await transfer(sourceDir, targetDir);
    expect(sent.ignoredPaths).toBe(0);
    expect(received.preservedIgnoredPaths).toBe(0);
    expect(await exists(path.join(targetDir, "node_modules"))).toBe(false);
  });

  it.skipIf(process.getuid?.() === 0)(
    "keeps the previous tree on disk when an ignored path cannot be carried over",
    async () => {
      const sourceDir = path.join(tmpRoot, "source");
      const targetDir = path.join(tmpRoot, "target");
      await writeTree(sourceDir, { ".beamsyncignore": "*.log\n", "a.txt": "new\n" });
      // An empty read-only directory on the source: nothing can be moved into it after the swap
      await mkdir(path.join(sourceDir, "locked"));
      await chmod(path.join(sourceDir, "locked"), 0o555);
      await writeTree(targetDir, { "a.txt": "old\n", "locked/run.log": "precious\n", "top.log": "t\n" });

      try {
        const { received } = await transfer(sourceDir, targetDir);
        expect(received.preservedIgnoredPaths).toBe(1); // top.log
        expect(received.preserveFailures.map((f) => f.relPath)).toEqual(["locked/run.log"]);
        expect(received.retainedBackupDir).toBeDefined();
        expect(await readFile(path.join(received.retainedBackupDir!, "locked/run.log"), "utf8")).toBe("precious\n");
        expect(await readFile(path.join(targetDir, "a.txt"), "utf8")).toBe("new\n");
        expect(await exists(path.join(targetDir, "top.log"))).toBe(true);
      } finally {
        await chmod(path.join(sourceDir, "locked"), 0o755).catch(() => {});
        await chmod(path.join(targetDir, "locked"), 0o755).catch(() => {});
      }
    },
  );

  it("rejects a malformed ignoreSpec before touching the target", async () => {
    const targetDir = path.join(tmpRoot, "target");
    await writeTree(targetDir, { "a.txt": "old\n" });
    expect(
      () =>
        new AtomicWorkspaceMaterializer({
          targetDir,
          sessionId: "0123456789abcdef",
          manifest: { version: "beamsync-tree/v1", totalLogicalBytes: 0, entries: [] },
          rootTreeDigest: "00",
          existingBlobs: new Map(),
          ignoreSpec: { version: 1, layers: [{ kind: "file", source: "x", baseDir: "", nameIndex: 0, lines: [42] }] } as never,
        }),
    ).toThrow(/Invalid ignoreSpec/);
    expect(await readFile(path.join(targetDir, "a.txt"), "utf8")).toBe("old\n");
  });

  it("carryOverIgnoredPaths never overwrites what the source sent", async () => {
    const oldRoot = path.join(tmpRoot, "old");
    const newRoot = path.join(tmpRoot, "new");
    await writeTree(oldRoot, { "cfg.local": "old\n", "dir/x.local": "old-x\n", "dir/y.txt": "y\n" });
    await writeTree(newRoot, { "cfg.local": "sent\n", "dir": "now a file\n" });
    const matcher = new LayeredIgnoreMatcher([
      { kind: "explicit", source: "t", baseDir: "", nameIndex: 0, lines: ["*.local"] },
    ]);
    const res = await carryOverIgnoredPaths(oldRoot, newRoot, matcher);
    expect(res).toEqual({ moved: 0, failures: [] });
    expect(await readFile(path.join(newRoot, "cfg.local"), "utf8")).toBe("sent\n");
    expect(await readFile(path.join(newRoot, "dir"), "utf8")).toBe("now a file\n");
  });
});
