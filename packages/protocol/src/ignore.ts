/**
 * Layered ignore rules with `.gitignore` pattern semantics.
 *
 * Rules come from several sources ("layers"). Each layer is anchored at a directory of the
 * workspace, and the last matching rule across all layers (lowest to highest precedence)
 * decides, exactly like git. Paths are tested top-down by the directory walkers: once a
 * directory is ignored it is never entered, so nothing below it can be re-included.
 */

/** Internal state that is never transferred and can never be re-included by a `!` rule. */
export const BUILTIN_IGNORE_PATTERNS = [
  ".beamsync/",
  ".beamsync-*",
  ".sync-staging-*",
  ".DS_Store",
];

export type IgnoreLayerKind =
  /** Rules file outside the workspace (`--ignore-from`): lowest precedence. */
  | "from"
  /** Ignore file found inside the workspace (`.beamsyncignore`, `.gitignore`, ...). */
  | "file"
  /** Explicit rules (`--ignore`, SDK `extraIgnoreRules`): highest precedence. */
  | "explicit";

export interface IgnoreLayer {
  kind: IgnoreLayerKind;
  /** Where the rules came from, for diagnostics (file path or "--ignore"). */
  source: string;
  /** Workspace-relative directory the patterns are anchored at ("" for the root). */
  baseDir: string;
  /** Position of the ignore file name in the configured list (later names win). */
  nameIndex: number;
  lines: string[];
}

/** Everything a receiver needs to evaluate the sender's ignore decisions on its own tree. */
export interface IgnoreSpec {
  version: 1;
  layers: IgnoreLayer[];
}

interface CompiledRule {
  negated: boolean;
  dirOnly: boolean;
  /** Pattern contains a slash: matched against the path relative to the layer's baseDir. */
  anchored: boolean;
  regex: RegExp;
  pattern: string;
}

export interface IgnoreDecision {
  ignored: boolean;
  /** The rule that decided, when one matched. */
  pattern?: string;
  source?: string;
  builtin?: boolean;
}

function stripTrailingSpaces(line: string): string {
  let end = line.length;
  while (end > 0 && line[end - 1] === " ") {
    // A backslash-escaped space is part of the pattern
    let backslashes = 0;
    for (let i = end - 2; i >= 0 && line[i] === "\\"; i--) backslashes++;
    if (backslashes % 2 === 1) break;
    end--;
  }
  return line.slice(0, end);
}

function escapeRegExpChar(ch: string): string {
  return /[\\^$.*+?()[\]{}|/-]/.test(ch) ? `\\${ch}` : ch;
}

const POSIX_CLASSES: Record<string, string> = {
  alnum: "a-zA-Z0-9",
  alpha: "a-zA-Z",
  digit: "0-9",
  lower: "a-z",
  upper: "A-Z",
  xdigit: "0-9a-fA-F",
  space: " \\t\\n\\r\\f\\v",
  blank: " \\t",
  punct: "!-\\/:-@\\[-`{-~",
};

/** Translates one path segment of a gitignore pattern (no `/` inside) into a regex fragment. */
function translateSegment(seg: string): string {
  let out = "";
  for (let i = 0; i < seg.length; i++) {
    const ch = seg[i];
    if (ch === "\\") {
      if (i + 1 < seg.length) {
        out += escapeRegExpChar(seg[i + 1]);
        i++;
      }
      continue;
    }
    if (ch === "*") {
      // Consecutive asterisks that are not a whole segment behave like a single one
      while (seg[i + 1] === "*") i++;
      out += "[^/]*";
      continue;
    }
    if (ch === "?") {
      out += "[^/]";
      continue;
    }
    if (ch === "[") {
      let j = i + 1;
      let negate = false;
      if (seg[j] === "!" || seg[j] === "^") {
        negate = true;
        j++;
      }
      let body = "";
      let closed = false;
      let first = true;
      for (; j < seg.length; j++) {
        const c = seg[j];
        if (c === "]" && !first) {
          closed = true;
          break;
        }
        first = false;
        if (c === "[" && seg[j + 1] === ":") {
          const close = seg.indexOf(":]", j + 2);
          const posix = close > 0 ? POSIX_CLASSES[seg.slice(j + 2, close)] : undefined;
          if (posix !== undefined) {
            body += posix;
            j = close + 1;
            continue;
          }
        }
        if (c === "\\" && j + 1 < seg.length) {
          body += `\\${seg[j + 1]}`;
          j++;
        } else if (c === "]" || c === "[" || c === "^") {
          body += `\\${c}`;
        } else {
          body += c;
        }
      }
      if (closed && body.length > 0) {
        out += `(?!/)[${negate ? "^" : ""}${body}]`;
        i = j;
        continue;
      }
      out += "\\[";
      continue;
    }
    out += escapeRegExpChar(ch);
  }
  return out;
}

export function compileIgnorePattern(rawLine: string): CompiledRule | null {
  let line = stripTrailingSpaces(rawLine.replace(/\r$/, ""));
  if (!line || line.startsWith("#")) return null;

  let negated = false;
  if (line.startsWith("!")) {
    negated = true;
    line = line.slice(1);
  }
  const pattern = line;

  let dirOnly = false;
  if (line.endsWith("/") && !line.endsWith("\\/")) {
    dirOnly = true;
    line = line.replace(/\/+$/, "");
  }
  if (!line) return null;

  const anchored = line.includes("/");
  if (line.startsWith("/")) line = line.slice(1);
  if (!line) return null;

  // Consecutive "**" segments are equivalent to one; collapsing them keeps the regex linear
  const segs = line.split("/").filter((seg, i, all) => !(seg === "**" && all[i - 1] === "**"));
  let re = "";
  for (let i = 0; i < segs.length; i++) {
    const seg = segs[i];
    const last = i === segs.length - 1;
    if (seg === "**" && segs.length > 1) {
      // Leading or inner "**/" spans zero or more directories; trailing "/**" is everything inside
      re += last ? ".+" : "(?:.*/)?";
    } else {
      re += translateSegment(seg) + (last ? "" : "/");
    }
  }

  let regex: RegExp;
  try {
    regex = new RegExp(`^${re}$`);
  } catch {
    return null; // Unparseable pattern (e.g. a reversed range): git skips it too
  }
  return { negated, dirOnly, anchored, regex, pattern: (negated ? "!" : "") + pattern };
}

interface CompiledLayer {
  layer: IgnoreLayer;
  depth: number;
  seq: number;
  rules: CompiledRule[];
}

const KIND_RANK: Record<IgnoreLayerKind, number> = { from: 0, file: 1, explicit: 2 };

function normalizeRel(relPath: string): string {
  return relPath.replace(/^\/+|\/+$/g, "");
}

function parentOf(rel: string): string {
  const idx = rel.lastIndexOf("/");
  return idx < 0 ? "" : rel.slice(0, idx);
}

export class LayeredIgnoreMatcher {
  private readonly builtin: CompiledRule[];
  /** Layers grouped by the directory they are anchored at. */
  private readonly byBaseDir = new Map<string, CompiledLayer[]>();
  private readonly all: CompiledLayer[] = [];
  /** Directory walks test siblings back to back, so remembering one directory is enough. */
  private cachedParent: string | null = null;
  private cachedLayers: CompiledLayer[] = [];

  constructor(layers: IgnoreLayer[] = []) {
    this.builtin = BUILTIN_IGNORE_PATTERNS.map((p) => compileIgnorePattern(p)).filter(
      (r): r is CompiledRule => r !== null,
    );
    for (const layer of layers) this.addLayer(layer);
  }

  static fromSpec(spec: IgnoreSpec | undefined | null): LayeredIgnoreMatcher {
    return new LayeredIgnoreMatcher(spec?.layers ?? []);
  }

  /** Number of user rules in effect (built-in patterns excluded). */
  get ruleCount(): number {
    return this.all.reduce((n, l) => n + l.rules.length, 0);
  }

  /** Adds a rule source. Returns the number of usable rules it contained. */
  addLayer(layer: IgnoreLayer): number {
    const baseDir = normalizeRel(layer.baseDir);
    const rules: CompiledRule[] = [];
    for (const line of layer.lines) {
      const rule = compileIgnorePattern(line);
      if (rule) rules.push(rule);
    }
    if (rules.length === 0) return 0;
    const compiled: CompiledLayer = {
      layer: { ...layer, baseDir },
      depth: baseDir === "" ? 0 : baseDir.split("/").length,
      seq: this.all.length,
      rules,
    };
    this.all.push(compiled);
    const bucket = this.byBaseDir.get(baseDir);
    if (bucket) bucket.push(compiled);
    else this.byBaseDir.set(baseDir, [compiled]);
    this.cachedParent = null;
    return rules.length;
  }

  toSpec(): IgnoreSpec {
    return { version: 1, layers: this.all.map((l) => l.layer) };
  }

  /** Built-in internal paths (staging directories, commit markers): never synced, never kept. */
  isBuiltinIgnored(relPath: string, isDirectory: boolean): boolean {
    const rel = normalizeRel(relPath);
    const base = rel.slice(rel.lastIndexOf("/") + 1);
    return this.builtin.some(
      (r) => (!r.dirOnly || isDirectory) && r.regex.test(r.anchored ? rel : base),
    );
  }

  /** Layers anchored at `dir` or one of its ancestors, lowest precedence first. */
  private layersFor(dir: string): CompiledLayer[] {
    if (this.cachedParent === dir) return this.cachedLayers;
    const found: CompiledLayer[] = [...(this.byBaseDir.get("") ?? [])];
    if (dir !== "") {
      let end = dir.indexOf("/");
      while (true) {
        const ancestor = end < 0 ? dir : dir.slice(0, end);
        const bucket = this.byBaseDir.get(ancestor);
        if (bucket) found.push(...bucket);
        if (end < 0) break;
        end = dir.indexOf("/", end + 1);
      }
    }
    // Source kind first, then ignore-file name order, then directory depth (deeper wins)
    found.sort(
      (a, b) =>
        KIND_RANK[a.layer.kind] - KIND_RANK[b.layer.kind] ||
        a.layer.nameIndex - b.layer.nameIndex ||
        a.depth - b.depth ||
        a.seq - b.seq,
    );
    this.cachedParent = dir;
    this.cachedLayers = found;
    return found;
  }

  explain(relPath: string, isDirectory: boolean): IgnoreDecision {
    const rel = normalizeRel(relPath);
    if (rel === "") return { ignored: false };
    if (this.isBuiltinIgnored(rel, isDirectory)) {
      return { ignored: true, builtin: true, source: "built-in" };
    }
    const base = rel.slice(rel.lastIndexOf("/") + 1);
    let decision: IgnoreDecision = { ignored: false };
    for (const { layer, rules } of this.layersFor(parentOf(rel))) {
      const local = layer.baseDir === "" ? rel : rel.slice(layer.baseDir.length + 1);
      for (const rule of rules) {
        if (rule.dirOnly && !isDirectory) continue;
        if (rule.regex.test(rule.anchored ? local : base)) {
          decision = { ignored: !rule.negated, pattern: rule.pattern, source: layer.source };
        }
      }
    }
    return decision;
  }

  ignores(relPath: string, isDirectory: boolean): boolean {
    return this.explain(relPath, isDirectory).ignored;
  }
}
