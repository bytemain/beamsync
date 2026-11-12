import net from "node:net";
import type dgram from "node:dgram";
import { randomBytes, type NatMappingBehavior } from "@beamsync/protocol";

const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

export interface StunReflexiveEndpoint {
  ip: string;
  port: number;
  family: 4 | 6;
}

export interface NatClassificationResult {
  endpoints: StunReflexiveEndpoint[];
  natMapping: NatMappingBehavior;
  portStride: number;
}

export function parseStunServerUrl(url: string): { host: string; port: number } {
  const stripped = url.replace(/^stun:/i, "").replace(/^\/\//, "").trim();
  if (stripped.startsWith("[")) {
    const closeBracket = stripped.indexOf("]");
    if (closeBracket > 0) {
      const host = stripped.slice(1, closeBracket);
      const rest = stripped.slice(closeBracket + 1);
      const port = rest.startsWith(":")
        ? Number.parseInt(rest.slice(1), 10) || 3478
        : 3478;
      return { host, port };
    }
  }
  const lastColon = stripped.lastIndexOf(":");
  if (lastColon > 0 && stripped.indexOf(":") === lastColon) {
    return {
      host: stripped.slice(0, lastColon),
      port: Number.parseInt(stripped.slice(lastColon + 1), 10) || 3478,
    };
  }
  return { host: stripped, port: 3478 };
}

function formatIpv6FromBytes(bytes: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    const word = (bytes[i] << 8) | bytes[i + 1];
    groups.push(word.toString(16));
  }
  const raw = groups.join(":");
  return net.isIPv6(raw) ? raw : groups.join(":");
}

export async function queryStunReflexiveAddress(
  socket: dgram.Socket,
  stunServerUrl: string,
  timeoutMs = 800,
): Promise<StunReflexiveEndpoint | null> {
  const { host, port } = parseStunServerUrl(stunServerUrl);
  const txId = Buffer.from(randomBytes(12));
  const req = Buffer.alloc(20);
  req.writeUInt16BE(STUN_BINDING_REQUEST, 0);
  req.writeUInt16BE(0, 2);
  req.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
  txId.copy(req, 8);

  return new Promise<StunReflexiveEndpoint | null>((resolve) => {
    let settled = false;
    const finish = (val: StunReflexiveEndpoint | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off("message", onMessage);
      resolve(val);
    };

    const onMessage = (msg: Buffer) => {
      if (msg.length < 20) return;
      const msgType = msg.readUInt16BE(0);
      const msgLen = msg.readUInt16BE(2);
      const cookie = msg.readUInt32BE(4);
      if (
        msgType !== STUN_BINDING_SUCCESS_RESPONSE ||
        cookie !== STUN_MAGIC_COOKIE
      ) {
        return;
      }
      if (!msg.subarray(8, 20).equals(txId)) {
        return;
      }

      let offset = 20;
      const end = Math.min(msg.length, 20 + msgLen);
      while (offset + 4 <= end) {
        const attrType = msg.readUInt16BE(offset);
        const attrLen = msg.readUInt16BE(offset + 2);
        const valStart = offset + 4;
        if (valStart + attrLen > end) break;

        if (
          attrType === STUN_ATTR_XOR_MAPPED_ADDRESS ||
          attrType === STUN_ATTR_MAPPED_ADDRESS
        ) {
          const family = msg[valStart + 1];
          if (family === 0x01 && attrLen >= 8) {
            const rawPort = msg.readUInt16BE(valStart + 2);
            const mappedPort =
              attrType === STUN_ATTR_XOR_MAPPED_ADDRESS
                ? (rawPort ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff
                : rawPort;

            const cookieBytes = Buffer.alloc(4);
            cookieBytes.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
            const ipOctets: number[] = [];
            for (let i = 0; i < 4; i++) {
              const b = msg[valStart + 4 + i];
              ipOctets.push(
                attrType === STUN_ATTR_XOR_MAPPED_ADDRESS
                  ? (b ^ cookieBytes[i]) & 0xff
                  : b,
              );
            }
            finish({ ip: ipOctets.join("."), port: mappedPort, family: 4 });
            return;
          }
          if (family === 0x02 && attrLen >= 20) {
            const rawPort = msg.readUInt16BE(valStart + 2);
            const mappedPort =
              attrType === STUN_ATTR_XOR_MAPPED_ADDRESS
                ? (rawPort ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff
                : rawPort;

            const xorMask = Buffer.alloc(16);
            xorMask.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
            txId.copy(xorMask, 4);

            const v6Bytes = new Uint8Array(16);
            for (let i = 0; i < 16; i++) {
              const b = msg[valStart + 4 + i];
              v6Bytes[i] =
                attrType === STUN_ATTR_XOR_MAPPED_ADDRESS
                  ? (b ^ xorMask[i]) & 0xff
                  : b;
            }
            finish({
              ip: formatIpv6FromBytes(v6Bytes),
              port: mappedPort,
              family: 6,
            });
            return;
          }
        }
        // Attributes are padded to 4-byte boundaries
        offset = valStart + ((attrLen + 3) & ~3);
      }
    };

    const timer = setTimeout(() => finish(null), timeoutMs);
    socket.on("message", onMessage);
    socket.send(req, port, host, (err) => {
      if (err) finish(null);
    });
  });
}

/**
 * Queries up to 2 distinct STUN servers on the exact same bound UDP socket
 * to determine whether the local NAT performs Endpoint-Independent Mapping (Cone NAT)
 * or Endpoint-Dependent Mapping (Symmetric NAT), plus any sequential port stride.
 */
export async function classifyNatMappingBehavior(
  socket: dgram.Socket,
  stunServers: string[],
  timeoutMs = 600,
): Promise<NatClassificationResult> {
  const uniqueUrls = Array.from(
    new Set(stunServers.map((s) => s.trim()).filter(Boolean)),
  ).slice(0, 3);

  const endpoints: StunReflexiveEndpoint[] = [];
  for (const url of uniqueUrls) {
    const ep = await queryStunReflexiveAddress(socket, url, timeoutMs);
    if (ep) {
      endpoints.push(ep);
      if (endpoints.length >= 2) break;
    }
  }

  if (endpoints.length < 2) {
    return {
      endpoints,
      natMapping: "unknown",
      portStride: 0,
    };
  }

  const [first, second] = endpoints;
  if (first.ip === second.ip && first.port === second.port) {
    return {
      endpoints,
      natMapping: "endpoint_independent",
      portStride: 0,
    };
  }

  return {
    endpoints,
    natMapping: "symmetric",
    portStride: second.port - first.port,
  };
}
