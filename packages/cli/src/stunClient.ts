import type dgram from "node:dgram";
import { randomBytes } from "@beamsync/protocol";

const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE = 0x0101;
const STUN_ATTR_MAPPED_ADDRESS = 0x0001;
const STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

export interface StunReflexiveEndpoint {
  ip: string;
  port: number;
}

export function parseStunServerUrl(url: string): { host: string; port: number } {
  const stripped = url.replace(/^stun:/i, "").replace(/^\/\//, "");
  const lastColon = stripped.lastIndexOf(":");
  if (lastColon > 0) {
    return {
      host: stripped.slice(0, lastColon),
      port: Number.parseInt(stripped.slice(lastColon + 1), 10) || 3478,
    };
  }
  return { host: stripped, port: 3478 };
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
          (attrType === STUN_ATTR_XOR_MAPPED_ADDRESS ||
            attrType === STUN_ATTR_MAPPED_ADDRESS) &&
          attrLen >= 8
        ) {
          const family = msg[valStart + 1];
          if (family === 0x01) {
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
            finish({ ip: ipOctets.join("."), port: mappedPort });
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
