import { execFile } from "node:child_process";
import dgram from "node:dgram";
import { readFile } from "node:fs/promises";
import net from "node:net";

/**
 * Gateway port mapping via NAT-PMP (RFC 6886).
 *
 * When the local router speaks NAT-PMP, asking it for an explicit UDP mapping turns a
 * hard-to-traverse NAT (symmetric / address-and-port dependent) into a stable public
 * `ip:port` the peer can dial directly, instead of relying on hole-punch timing.
 */

export const NAT_PMP_PORT = 5351;
export const NAT_PMP_DEFAULT_LIFETIME_SEC = 7200;

const OP_EXTERNAL_ADDRESS = 0;
const OP_MAP_UDP = 1;
const OP_MAP_TCP = 2;

export interface PortMappingGateway {
  address: string;
  port?: number;
}

export interface NatPmpMapping {
  protocol: "udp" | "tcp";
  gateway: Required<PortMappingGateway>;
  internalPort: number;
  externalIp: string;
  externalPort: number;
  lifetimeSec: number;
}

function isPrivateIpv4(ip: string): boolean {
  const p = ip.split(".").map((x) => Number.parseInt(x, 10));
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  return (
    p[0] === 10 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 100 && p[1] >= 64 && p[1] <= 127)
  );
}

/** Parses the Linux kernel routing table (`/proc/net/route`) for the default IPv4 gateway. */
export function parseLinuxDefaultGateway(procNetRoute: string): string | null {
  for (const line of procNetRoute.split("\n").slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4) continue;
    const [, destination, gatewayHex, flagsHex] = cols;
    const flags = Number.parseInt(flagsHex, 16);
    // RTF_UP (0x1) | RTF_GATEWAY (0x2) on the 0.0.0.0/0 route
    if (destination !== "00000000" || (flags & 0x3) !== 0x3) continue;
    if (!/^[0-9a-fA-F]{8}$/.test(gatewayHex)) continue;
    // The kernel prints the address in host (little-endian) byte order
    const octets = [6, 4, 2, 0].map((i) => Number.parseInt(gatewayHex.slice(i, i + 2), 16));
    const ip = octets.join(".");
    if (ip !== "0.0.0.0") return ip;
  }
  return null;
}

export async function discoverDefaultGatewayIpv4(): Promise<string | null> {
  try {
    if (process.platform === "linux") {
      return parseLinuxDefaultGateway(await readFile("/proc/net/route", "utf8"));
    }
    if (process.platform === "darwin" || process.platform === "freebsd") {
      const stdout = await new Promise<string>((resolve, reject) => {
        execFile("route", ["-n", "get", "default"], { timeout: 800 }, (err, out) =>
          err ? reject(err) : resolve(out),
        );
      });
      const m = stdout.match(/gateway:\s*(\d+\.\d+\.\d+\.\d+)/);
      return m ? m[1] : null;
    }
  } catch {
    // No routing table access: port mapping is simply skipped
  }
  return null;
}

/** One NAT-PMP request/response exchange with RFC 6886 style retransmission (doubling interval). */
function natPmpExchange(
  gateway: Required<PortMappingGateway>,
  request: Buffer,
  expectedOpcode: number,
  minResponseBytes: number,
  timeoutMs: number,
): Promise<Buffer | null> {
  return new Promise((resolve) => {
    const socket = dgram.createSocket("udp4");
    let done = false;
    let retryTimer: NodeJS.Timeout | null = null;
    const finish = (result: Buffer | null) => {
      if (done) return;
      done = true;
      clearTimeout(deadline);
      if (retryTimer) clearTimeout(retryTimer);
      try {
        socket.close();
      } catch {
        // already closed
      }
      resolve(result);
    };
    const deadline = setTimeout(() => finish(null), timeoutMs);

    socket.on("error", () => finish(null));
    socket.on("message", (msg, rinfo) => {
      // Only the gateway we asked may answer (RFC 6886 §3.1)
      if (rinfo.address !== gateway.address || rinfo.port !== gateway.port) return;
      if (msg.length < minResponseBytes || msg[0] !== 0 || msg[1] !== 128 + expectedOpcode) return;
      finish(msg);
    });

    let intervalMs = 120;
    const transmit = () => {
      if (done) return;
      socket.send(request, gateway.port, gateway.address, () => {});
      retryTimer = setTimeout(transmit, intervalMs);
      intervalMs *= 2;
    };
    transmit();
  });
}

async function sendMapRequest(
  gateway: Required<PortMappingGateway>,
  protocol: "udp" | "tcp",
  internalPort: number,
  suggestedExternalPort: number,
  lifetimeSec: number,
  timeoutMs: number,
): Promise<{ externalPort: number; lifetimeSec: number } | null> {
  const opcode = protocol === "udp" ? OP_MAP_UDP : OP_MAP_TCP;
  const req = Buffer.alloc(12);
  req[0] = 0;
  req[1] = opcode;
  req.writeUInt16BE(internalPort, 4);
  req.writeUInt16BE(suggestedExternalPort, 6);
  req.writeUInt32BE(lifetimeSec, 8);
  const res = await natPmpExchange(gateway, req, opcode, 16, timeoutMs);
  if (!res || res.readUInt16BE(2) !== 0 || res.readUInt16BE(8) !== internalPort) return null;
  return { externalPort: res.readUInt16BE(10), lifetimeSec: res.readUInt32BE(12) };
}

/**
 * Asks the gateway for its external address and a mapping `external:port -> this host:internalPort`.
 * Resolves `null` when the gateway does not speak NAT-PMP, refuses, or stays silent.
 */
export async function requestNatPmpMapping(params: {
  gateway: PortMappingGateway;
  protocol: "udp" | "tcp";
  internalPort: number;
  lifetimeSec?: number;
  timeoutMs?: number;
}): Promise<NatPmpMapping | null> {
  const gateway = { address: params.gateway.address, port: params.gateway.port ?? NAT_PMP_PORT };
  const timeoutMs = params.timeoutMs ?? 400;
  const lifetimeSec = params.lifetimeSec ?? NAT_PMP_DEFAULT_LIFETIME_SEC;
  if (!net.isIPv4(gateway.address)) return null;

  // Both questions go out together so a silent gateway costs a single timeout
  const [addrRes, mapRes] = await Promise.all([
    natPmpExchange(gateway, Buffer.from([0, OP_EXTERNAL_ADDRESS]), OP_EXTERNAL_ADDRESS, 12, timeoutMs),
    sendMapRequest(gateway, params.protocol, params.internalPort, params.internalPort, lifetimeSec, timeoutMs),
  ]);
  if (!mapRes) return null;
  if (!addrRes || addrRes.readUInt16BE(2) !== 0) {
    // A mapping without a usable external address cannot be advertised: give it back
    void releaseNatPmpMapping({
      protocol: params.protocol,
      gateway,
      internalPort: params.internalPort,
    });
    return null;
  }
  const externalIp = Array.from(addrRes.subarray(8, 12)).join(".");
  if (externalIp === "0.0.0.0" || mapRes.externalPort === 0 || mapRes.lifetimeSec === 0) {
    void releaseNatPmpMapping({
      protocol: params.protocol,
      gateway,
      internalPort: params.internalPort,
    });
    return null;
  }
  return {
    protocol: params.protocol,
    gateway,
    internalPort: params.internalPort,
    externalIp,
    externalPort: mapRes.externalPort,
    lifetimeSec: mapRes.lifetimeSec,
  };
}

/** Deletes a mapping (lifetime 0, external port 0 per RFC 6886 §3.4). Best effort. */
export async function releaseNatPmpMapping(
  mapping: Pick<NatPmpMapping, "protocol" | "gateway" | "internalPort">,
  timeoutMs = 250,
): Promise<boolean> {
  const res = await sendMapRequest(
    mapping.gateway,
    mapping.protocol,
    mapping.internalPort,
    0,
    0,
    timeoutMs,
  );
  return res !== null;
}

export interface ActivePortMapping {
  mapping: NatPmpMapping;
  /** Stops lifetime renewal and deletes the mapping on the gateway. */
  release(): Promise<void>;
}

/**
 * Discovers the default gateway (unless one is given), requests a mapping, and keeps it alive
 * by renewing at half its lifetime until released.
 */
export async function acquirePortMapping(params: {
  protocol: "udp" | "tcp";
  internalPort: number;
  gateway?: PortMappingGateway;
  lifetimeSec?: number;
  timeoutMs?: number;
}): Promise<ActivePortMapping | null> {
  let gateway = params.gateway;
  if (!gateway) {
    const discovered = await discoverDefaultGatewayIpv4();
    // A gateway on a public address is a routed link, not a NAT that could map ports for us
    if (!discovered || !isPrivateIpv4(discovered)) return null;
    gateway = { address: discovered };
  }
  const mapping = await requestNatPmpMapping({ ...params, gateway });
  if (!mapping) return null;

  let released = false;
  let renewTimer: NodeJS.Timeout | null = null;
  const scheduleRenewal = (lifetimeSec: number) => {
    renewTimer = setTimeout(
      () => {
        if (released) return;
        void sendMapRequest(
          mapping.gateway,
          mapping.protocol,
          mapping.internalPort,
          mapping.externalPort,
          mapping.lifetimeSec,
          2000,
        ).then((res) => {
          if (!released) scheduleRenewal(res?.lifetimeSec || lifetimeSec);
        });
      },
      Math.max(5, lifetimeSec / 2) * 1000,
    );
    renewTimer.unref();
  };
  scheduleRenewal(mapping.lifetimeSec);

  return {
    mapping,
    release: async () => {
      if (released) return;
      released = true;
      if (renewTimer) clearTimeout(renewTimer);
      await releaseNatPmpMapping(mapping);
    },
  };
}
