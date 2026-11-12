import type { IgnoreOptions } from "./stateIndex.js";

/** Flags that never take a value, so `--respect-gitignore ./dir` keeps `./dir` positional. */
const BOOLEAN_FLAGS = new Set([
  "help",
  "prefer-edge-relay",
  "disable-edge-relay",
  "no-optimistic-relay",
  "no-port-mapping",
  "no-udp-mtu-probe",
  "respect-gitignore",
  "delete-ignored",
  "json",
]);

export function parseArgs(argv: string[]): {
  positional: string[];
  /** Last value wins. */
  flags: Record<string, string | boolean>;
  /** Every value of a repeated flag, in order (`--ignore a --ignore b`). */
  multi: Record<string, string[]>;
} {
  const positional: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const multi: Record<string, string[]> = {};
  const setValue = (key: string, value: string): void => {
    flags[key] = value;
    (multi[key] ??= []).push(value);
  };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      positional.push(arg);
      continue;
    }
    const eq = arg.indexOf("=");
    if (eq > 2) {
      setValue(arg.slice(2, eq), arg.slice(eq + 1));
      continue;
    }
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!BOOLEAN_FLAGS.has(key) && next !== undefined && !next.startsWith("--")) {
      setValue(key, next);
      i++;
    } else {
      flags[key] = true;
    }
  }
  return { positional, flags, multi };
}

/** Collects the ignore flags shared by `send` and `ignored`. */
export function ignoreOptionsFromArgs(
  flags: Record<string, string | boolean>,
  multi: Record<string, string[]>,
  env: NodeJS.ProcessEnv = process.env,
): IgnoreOptions {
  const splitNames = (values: string[]): string[] =>
    values.flatMap((v) => v.split(",")).map((v) => v.trim()).filter(Boolean);
  for (const key of ["ignore", "ignore-file", "ignore-from"]) {
    if (flags[key] === true) throw new Error(`--${key} requires a value`);
  }
  return {
    // Environment first so names given on the command line take precedence
    ignoreFileNames: [
      ...splitNames(env.BEAMSYNC_IGNORE_FILES ? [env.BEAMSYNC_IGNORE_FILES] : []),
      ...splitNames(multi["ignore-file"] ?? []),
    ],
    respectGitignore: Boolean(flags["respect-gitignore"]),
    extraIgnoreRules: multi.ignore ?? [],
    ignoreFromFiles: multi["ignore-from"] ?? [],
  };
}
