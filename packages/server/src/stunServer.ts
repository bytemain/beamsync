import dgram from "node:dgram";

export const STUN_MAGIC_COOKIE = 0x2112a442;
const STUN_BINDING_REQUEST = 0x0001;
const STUN_BINDING_SUCCESS_RESPONSE = 0x0101;
const STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

export interface RunningStunServer {
  port: number;
  close(): Promise<void>;
}

/**
 * Minimal RFC 5389 UDP STUN Binding responder returning XOR-MAPPED-ADDRESS (0x0020).
 * Allows BeamSync's standalone server to provide NAT reflexive address discovery
 * without any external STUN dependency.
 */
export async function startUdpStunServer(
  port = 3478,
  host = "0.0.0.0",
): Promise<RunningStunServer> {
  const sock = dgram.createSocket("udp4");

  sock.on("message", (msg, rinfo) => {
    if (msg.length < 20) return;
    const msgType = msg.readUInt16BE(0);
    const cookie = msg.readUInt32BE(4);
    if (msgType !== STUN_BINDING_REQUEST || cookie !== STUN_MAGIC_COOKIE) {
      return;
    }
    const txId = msg.subarray(8, 20);
    const ipParts = rinfo.address.split(".").map((x) => Number.parseInt(x, 10));
    if (ipParts.length !== 4 || ipParts.some((n) => Number.isNaN(n))) {
      return;
    }

    // Attr: Type (2B) + Length (2B = 8) + Reserved (1B) + Family (1B = 0x01 IPv4) + X-Port (2B) + X-Address (4B)
    const attr = Buffer.alloc(12);
    attr.writeUInt16BE(STUN_ATTR_XOR_MAPPED_ADDRESS, 0);
    attr.writeUInt16BE(8, 2);
    attr[4] = 0x00;
    attr[5] = 0x01; // IPv4
    const xPort = (rinfo.port ^ (STUN_MAGIC_COOKIE >>> 16)) & 0xffff;
    attr.writeUInt16BE(xPort, 6);

    const cookieBytes = Buffer.alloc(4);
    cookieBytes.writeUInt32BE(STUN_MAGIC_COOKIE, 0);
    for (let i = 0; i < 4; i++) {
      attr[8 + i] = (ipParts[i] ^ cookieBytes[i]) & 0xff;
    }

    const header = Buffer.alloc(20);
    header.writeUInt16BE(STUN_BINDING_SUCCESS_RESPONSE, 0);
    header.writeUInt16BE(attr.length, 2);
    header.writeUInt32BE(STUN_MAGIC_COOKIE, 4);
    txId.copy(header, 8);

    const response = Buffer.concat([header, attr]);
    sock.send(response, rinfo.port, rinfo.address);
  });

  await new Promise<void>((resolve, reject) => {
    sock.once("error", reject);
    sock.bind(port, host, () => {
      sock.removeListener("error", reject);
      resolve();
    });
  });

  const addr = sock.address();
  const boundPort = typeof addr === "string" ? port : addr.port;

  return {
    port: boundPort,
    close: () =>
      new Promise<void>((resolve) => {
        sock.close(() => resolve());
      }),
  };
}
