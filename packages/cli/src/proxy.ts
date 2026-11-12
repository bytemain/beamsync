import crypto from "node:crypto";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import { constantTimeEqual, utf8Bytes } from "@beamsync/protocol";

/**
 * Outbound proxy support for every TCP-based control and data path that leaves the
 * host through HTTP(S)/WebSocket: Coordinator REST + signaling, Edge Relay WSS
 * (including pinned IP+TLS / SNI-free nodes), and R2 presigned PUT/GET.
 *
 * Direct P2P sockets, same-host IPC, and UDP never use a proxy.
 */
export interface ProxyConfig {
  protocol: "http" | "https" | "socks5";
  host: string;
  port: number;
  username?: string;
  password?: string;
  /** Redacted display form (no credentials). */
  display: string;
}

type EnvMap = Record<string, string | undefined>;

function readEnv(env: EnvMap, ...names: string[]): string | undefined {
  for (const name of names) {
    const v = env[name] ?? env[name.toLowerCase()] ?? env[name.toUpperCase()];
    if (v && v.trim()) return v.trim();
  }
  return undefined;
}

export function parseProxyUrl(raw: string): ProxyConfig {
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  const u = new URL(withScheme);
  const scheme = u.protocol.replace(/:$/, "").toLowerCase();
  let protocol: ProxyConfig["protocol"];
  if (scheme === "http") protocol = "http";
  else if (scheme === "https") protocol = "https";
  else if (scheme === "socks5" || scheme === "socks5h" || scheme === "socks") {
    protocol = "socks5";
  } else {
    throw new Error(`Unsupported proxy scheme "${scheme}" (use http, https, or socks5)`);
  }
  const defaultPort = protocol === "socks5" ? 1080 : protocol === "https" ? 443 : 80;
  const host = u.hostname.replace(/^\[|\]$/g, "");
  const port = u.port ? Number(u.port) : defaultPort;
  return {
    protocol,
    host,
    port,
    username: u.username ? decodeURIComponent(u.username) : undefined,
    password: u.password ? decodeURIComponent(u.password) : undefined,
    display: `${protocol}://${u.hostname}:${port}`,
  };
}

function ipv4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, part) => ((acc << 8) | (Number(part) & 0xff)) >>> 0, 0);
}

/** Evaluates a standard `NO_PROXY` list: `*`, exact hosts, domain suffixes, `host:port`, IPv4 CIDR. */
export function isHostBypassedByNoProxy(
  host: string,
  port: number,
  noProxy: string | undefined,
): boolean {
  if (!noProxy) return false;
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  for (const rawEntry of noProxy.split(/[\s,]+/)) {
    let entry = rawEntry.trim().toLowerCase();
    if (!entry) continue;
    if (entry === "*") return true;

    if (entry.includes("/") && net.isIPv4(h)) {
      const [base, bitsRaw] = entry.split("/");
      const bits = Number(bitsRaw);
      if (net.isIPv4(base) && Number.isInteger(bits) && bits >= 0 && bits <= 32) {
        const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
        if ((ipv4ToInt(h) & mask) >>> 0 === (ipv4ToInt(base) & mask) >>> 0) return true;
      }
      continue;
    }

    let entryPort: number | null = null;
    const bracketed = entry.match(/^\[([^\]]+)\](?::(\d+))?$/);
    if (bracketed) {
      entry = bracketed[1];
      entryPort = bracketed[2] ? Number(bracketed[2]) : null;
    } else if (!net.isIPv6(entry)) {
      const m = entry.match(/^(.*):(\d+)$/);
      if (m) {
        entry = m[1];
        entryPort = Number(m[2]);
      }
    }
    if (entryPort !== null && entryPort !== port) continue;

    const bare = entry.replace(/^\*?\./, "");
    if (h === bare || h.endsWith(`.${bare}`)) return true;
  }
  return false;
}

/**
 * Resolves the proxy for a target URL.
 * Precedence: `BEAMSYNC_PROXY` > `HTTPS_PROXY` (https/wss) or `HTTP_PROXY` (http/ws) > `ALL_PROXY`.
 * `NO_PROXY` / `BEAMSYNC_NO_PROXY` exclusions always win.
 */
export function resolveProxyForUrl(
  targetUrl: string | URL,
  env: EnvMap = process.env,
): ProxyConfig | null {
  const u = typeof targetUrl === "string" ? new URL(targetUrl) : targetUrl;
  const secure = u.protocol === "https:" || u.protocol === "wss:";
  const port = u.port ? Number(u.port) : secure ? 443 : 80;

  const noProxy = [readEnv(env, "BEAMSYNC_NO_PROXY"), readEnv(env, "NO_PROXY")]
    .filter(Boolean)
    .join(",");
  if (isHostBypassedByNoProxy(u.hostname, port, noProxy)) return null;

  const raw =
    readEnv(env, "BEAMSYNC_PROXY") ??
    (secure ? readEnv(env, "HTTPS_PROXY") : readEnv(env, "HTTP_PROXY")) ??
    readEnv(env, "ALL_PROXY");
  if (!raw) return null;
  return parseProxyUrl(raw);
}

function formatAuthority(host: string, port: number): string {
  return net.isIPv6(host) ? `[${host}]:${port}` : `${host}:${port}`;
}

/** Reads from `sock` until `isComplete` returns a consumed-length, pushing surplus bytes back. */
function readUntil(
  sock: net.Socket,
  isComplete: (buf: Buffer) => number | null,
  timeoutMs: number,
  label: string,
): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    let acc: Buffer = Buffer.alloc(0);
    const cleanup = () => {
      clearTimeout(timer);
      sock.off("data", onData);
      sock.off("error", onError);
      sock.off("close", onClose);
    };
    const onData = (chunk: Buffer) => {
      acc = acc.length === 0 ? chunk : Buffer.concat([acc, chunk]);
      const consumed = isComplete(acc);
      if (consumed === null) return;
      cleanup();
      sock.pause();
      const rest = acc.subarray(consumed);
      if (rest.length > 0) sock.unshift(rest);
      resolve(acc.subarray(0, consumed));
    };
    const onError = (err: Error) => {
      cleanup();
      reject(err);
    };
    const onClose = () => {
      cleanup();
      reject(new Error(`PROXY_CONNECT_FAILED: proxy closed during ${label}`));
    };
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error(`PROXY_CONNECT_FAILED: timed out during ${label}`));
    }, timeoutMs);
    sock.on("data", onData);
    sock.once("error", onError);
    sock.once("close", onClose);
    sock.resume();
  });
}

async function connectToProxyServer(
  proxy: ProxyConfig,
  timeoutMs: number,
): Promise<net.Socket> {
  return new Promise<net.Socket>((resolve, reject) => {
    const onError = (err: Error) => {
      clearTimeout(timer);
      reject(new Error(`PROXY_CONNECT_FAILED: ${proxy.display}: ${err.message}`));
    };
    const sock: net.Socket =
      proxy.protocol === "https"
        ? tls.connect({
            host: proxy.host,
            port: proxy.port,
            servername: net.isIP(proxy.host) ? undefined : proxy.host,
          })
        : net.connect({ host: proxy.host, port: proxy.port });
    const timer = setTimeout(() => {
      sock.destroy();
      reject(new Error(`PROXY_CONNECT_FAILED: timed out connecting to ${proxy.display}`));
    }, timeoutMs);
    sock.once("error", onError);
    sock.once(proxy.protocol === "https" ? "secureConnect" : "connect", () => {
      clearTimeout(timer);
      sock.off("error", onError);
      sock.setNoDelay(true);
      resolve(sock);
    });
  });
}

async function httpConnectHandshake(
  sock: net.Socket,
  proxy: ProxyConfig,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<void> {
  const authority = formatAuthority(host, port);
  const lines = [
    `CONNECT ${authority} HTTP/1.1`,
    `Host: ${authority}`,
    "Proxy-Connection: Keep-Alive",
  ];
  if (proxy.username !== undefined) {
    const token = Buffer.from(`${proxy.username}:${proxy.password ?? ""}`).toString("base64");
    lines.push(`Proxy-Authorization: Basic ${token}`);
  }
  sock.write(`${lines.join("\r\n")}\r\n\r\n`);

  const head = await readUntil(
    sock,
    (buf) => {
      const idx = buf.indexOf("\r\n\r\n");
      if (idx >= 0) return idx + 4;
      if (buf.length > 16 * 1024) return buf.length;
      return null;
    },
    timeoutMs,
    "HTTP CONNECT",
  );
  const statusLine = head.toString("latin1").split("\r\n", 1)[0] ?? "";
  const m = statusLine.match(/^HTTP\/1\.[01] (\d{3})/);
  const status = m ? Number(m[1]) : 0;
  if (status !== 200) {
    throw new Error(
      `PROXY_CONNECT_FAILED: ${proxy.display} answered "${statusLine || "malformed response"}" for ${authority}`,
    );
  }
}

async function socks5Handshake(
  sock: net.Socket,
  proxy: ProxyConfig,
  host: string,
  port: number,
  timeoutMs: number,
): Promise<void> {
  const hasCreds = proxy.username !== undefined;
  sock.write(Buffer.from(hasCreds ? [0x05, 0x02, 0x00, 0x02] : [0x05, 0x01, 0x00]));
  const choice = await readUntil(sock, (b) => (b.length >= 2 ? 2 : null), timeoutMs, "SOCKS5 greeting");
  if (choice[0] !== 0x05) {
    throw new Error("PROXY_CONNECT_FAILED: peer is not a SOCKS5 proxy");
  }
  if (choice[1] === 0x02) {
    const user = Buffer.from(proxy.username ?? "", "utf8");
    const pass = Buffer.from(proxy.password ?? "", "utf8");
    if (user.length > 255 || pass.length > 255) {
      throw new Error("PROXY_CONNECT_FAILED: SOCKS5 credentials exceed 255 bytes");
    }
    sock.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]));
    const authRes = await readUntil(sock, (b) => (b.length >= 2 ? 2 : null), timeoutMs, "SOCKS5 auth");
    if (authRes[1] !== 0x00) {
      throw new Error("PROXY_CONNECT_FAILED: SOCKS5 username/password rejected");
    }
  } else if (choice[1] !== 0x00) {
    throw new Error("PROXY_CONNECT_FAILED: SOCKS5 proxy offered no acceptable auth method");
  }

  let addr: Buffer;
  if (net.isIPv4(host)) {
    addr = Buffer.concat([Buffer.from([0x01]), Buffer.from(host.split(".").map(Number))]);
  } else if (net.isIPv6(host)) {
    // Expand to 16 raw bytes
    const [headPart, tailPart = ""] = host.split("::");
    const headGroups = headPart ? headPart.split(":") : [];
    const tailGroups = tailPart ? tailPart.split(":") : [];
    const missing = host.includes("::") ? 8 - headGroups.length - tailGroups.length : 0;
    const groups = [...headGroups, ...new Array<string>(missing).fill("0"), ...tailGroups];
    const raw = Buffer.alloc(16);
    groups.forEach((g, i) => raw.writeUInt16BE(parseInt(g || "0", 16), i * 2));
    addr = Buffer.concat([Buffer.from([0x04]), raw]);
  } else {
    // Domain form: the proxy resolves DNS (socks5h semantics), which is what restricted networks need
    const name = Buffer.from(host, "utf8");
    if (name.length > 255) {
      throw new Error("PROXY_CONNECT_FAILED: hostname too long for SOCKS5");
    }
    addr = Buffer.concat([Buffer.from([0x03, name.length]), name]);
  }
  const portBuf = Buffer.alloc(2);
  portBuf.writeUInt16BE(port, 0);
  sock.write(Buffer.concat([Buffer.from([0x05, 0x01, 0x00]), addr, portBuf]));

  const reply = await readUntil(
    sock,
    (b) => {
      if (b.length < 5) return null;
      const atyp = b[3];
      const need = atyp === 0x01 ? 10 : atyp === 0x04 ? 22 : atyp === 0x03 ? 7 + b[4] : 10;
      return b.length >= need ? need : null;
    },
    timeoutMs,
    "SOCKS5 connect",
  );
  if (reply[1] !== 0x00) {
    throw new Error(
      `PROXY_CONNECT_FAILED: SOCKS5 connect to ${formatAuthority(host, port)} refused (code ${reply[1]})`,
    );
  }
}

/** Opens a raw TCP tunnel to `host:port` through an HTTP CONNECT or SOCKS5 proxy. */
export async function openProxyTunnel(
  proxy: ProxyConfig,
  host: string,
  port: number,
  timeoutMs = 10_000,
): Promise<net.Socket> {
  const sock = await connectToProxyServer(proxy, timeoutMs);
  try {
    if (proxy.protocol === "socks5") {
      await socks5Handshake(sock, proxy, host, port, timeoutMs);
    } else {
      await httpConnectHandshake(sock, proxy, host, port, timeoutMs);
    }
    return sock;
  } catch (err) {
    sock.destroy();
    throw err;
  }
}

/**
 * Destroys `sock` with `EDGE_RELAY_CERT_PIN_MISMATCH` unless the peer leaf
 * certificate's SHA-256 equals `expectedPin`. Must run before any application write.
 */
export function attachCertPinCheck(sock: tls.TLSSocket, expectedPin: string): void {
  sock.prependOnceListener("secureConnect", () => {
    const peerCert = sock.getPeerCertificate(false);
    if (!peerCert || !peerCert.raw || peerCert.raw.length === 0) {
      sock.destroy(new Error("EDGE_RELAY_CERT_PIN_MISMATCH: missing peer certificate"));
      return;
    }
    const actualSha256 = crypto
      .createHash("sha256")
      .update(peerCert.raw)
      .digest("hex")
      .toLowerCase();
    if (
      expectedPin.length !== actualSha256.length ||
      !constantTimeEqual(utf8Bytes(actualSha256), utf8Bytes(expectedPin))
    ) {
      sock.destroy(
        new Error(`EDGE_RELAY_CERT_PIN_MISMATCH: expected ${expectedPin}, got ${actualSha256}`),
      );
    }
  });
}

type CreateConnectionCallback = (err: Error | null, socket?: net.Socket) => void;

/**
 * Builds an `http.Agent` / `https.Agent` whose sockets are tunneled through `proxy`.
 * For TLS targets the handshake still terminates end-to-end at the origin, so
 * certificate pinning (`certSha256`) and SNI suppression (`noSni`) keep working.
 */
export function createProxyTunnelAgent(params: {
  proxy: ProxyConfig;
  secure: boolean;
  certSha256?: string;
  noSni?: boolean;
  keepAlive?: boolean;
}): http.Agent {
  const expectedPin = params.certSha256?.trim().toLowerCase();
  const agent: http.Agent = params.secure
    ? new https.Agent({ keepAlive: Boolean(params.keepAlive) })
    : new http.Agent({ keepAlive: Boolean(params.keepAlive) });

  (agent as unknown as {
    createConnection: (
      options: { host?: string; hostname?: string; port?: number | string },
      cb: CreateConnectionCallback,
    ) => void;
  }).createConnection = (options, cb) => {
    const host = String(options.hostname ?? options.host ?? "localhost").replace(/^\[|\]$/g, "");
    const port = Number(options.port ?? (params.secure ? 443 : 80));
    openProxyTunnel(params.proxy, host, port)
      .then((raw) => {
        if (!params.secure) {
          raw.resume();
          cb(null, raw);
          return;
        }
        const tlsSock = tls.connect({
          socket: raw,
          host,
          servername: params.noSni || net.isIP(host) ? "" : host,
          rejectUnauthorized: expectedPin ? false : true,
        });
        if (expectedPin) {
          attachCertPinCheck(tlsSock, expectedPin);
        }
        cb(null, tlsSock);
      })
      .catch((err) => cb(err instanceof Error ? err : new Error(String(err))));
  };
  return agent;
}
