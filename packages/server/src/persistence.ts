import { appendFile, mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { CasPackRecord, CoordinatorPersistenceHook } from "@beamsync/coordinator";

type JournalLine =
  | { op: "upsert"; record: CasPackRecord }
  | { op: "delete"; scopeNamespace: string; packId: string };

/**
 * Crash-safe append-only JSONL WAL with startup compaction for CAS pack metadata.
 * Avoids native C++ addons so container images stay small and portable across architectures.
 */
export class FileWalPersistence implements CoordinatorPersistenceHook {
  private readonly dir: string;
  private readonly walPath: string;
  private writeChain: Promise<void> = Promise.resolve();

  constructor(dataDir: string) {
    this.dir = dataDir;
    this.walPath = path.join(dataDir, "cas-packs.wal.jsonl");
  }

  async loadCasPacks(): Promise<CasPackRecord[]> {
    await mkdir(this.dir, { recursive: true });
    let raw = "";
    try {
      raw = await readFile(this.walPath, "utf8");
    } catch {
      return [];
    }

    const map = new Map<string, CasPackRecord>();
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      try {
        const entry = JSON.parse(trimmed) as JournalLine;
        if (entry.op === "upsert") {
          map.set(`${entry.record.scopeNamespace}:${entry.record.packId}`, entry.record);
        } else if (entry.op === "delete") {
          map.delete(`${entry.scopeNamespace}:${entry.packId}`);
        }
      } catch {
        // Ignore truncated tail line if crashed mid-write
      }
    }

    // Compact snapshot atomically on load
    const records = Array.from(map.values());
    const compacted = records
      .map((r) => JSON.stringify({ op: "upsert", record: r } satisfies JournalLine))
      .join("\n");
    const tmpPath = `${this.walPath}.tmp`;
    await writeFile(tmpPath, compacted ? `${compacted}\n` : "", "utf8");
    await rename(tmpPath, this.walPath);

    return records;
  }

  async upsertCasPack(record: CasPackRecord): Promise<void> {
    await this.enqueueLine({ op: "upsert", record });
  }

  async deleteCasPack(scopeNamespace: string, packId: string): Promise<void> {
    await this.enqueueLine({ op: "delete", scopeNamespace, packId });
  }

  private enqueueLine(entry: JournalLine): Promise<void> {
    this.writeChain = this.writeChain.then(async () => {
      await mkdir(this.dir, { recursive: true });
      await appendFile(this.walPath, `${JSON.stringify(entry)}\n`, "utf8");
    });
    return this.writeChain;
  }
}
