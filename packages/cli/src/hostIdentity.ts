import { readFile } from "node:fs/promises";
import os from "node:os";
import { computeHostFingerprint } from "@beamsync/protocol";

async function readFirstAvailable(paths: string[]): Promise<string | null> {
  for (const p of paths) {
    try {
      const content = (await readFile(p, "utf8")).trim();
      if (content) return content;
    } catch {
      // Try next path
    }
  }
  return null;
}

export async function readLocalHostRawIdentity(): Promise<{
  machineId: string;
  bootId: string;
}> {
  const machineId =
    (await readFirstAvailable([
      "/etc/machine-id",
      "/var/lib/dbus/machine-id",
    ])) ?? `host:${os.hostname()}:${os.platform()}:${os.arch()}`;

  const bootId =
    (await readFirstAvailable(["/proc/sys/kernel/random/boot_id"])) ??
    `boot:${Math.floor(Date.now() / 1000 - os.uptime())}`;

  return { machineId, bootId };
}

export async function buildSessionHostFingerprint(
  hostFingerprintKey: Uint8Array,
  overrideHostId?: string,
): Promise<string> {
  if (overrideHostId) {
    return computeHostFingerprint(hostFingerprintKey, overrideHostId, "override");
  }
  const { machineId, bootId } = await readLocalHostRawIdentity();
  return computeHostFingerprint(hostFingerprintKey, machineId, bootId);
}
