import http from "node:http";
import https from "node:https";
import { selectTransportAgent } from "./edgeRelayChannel.js";
import { resolveProxyForUrl } from "./proxy.js";

export interface HttpResponseBytes {
  status: number;
  body: Buffer;
}

// One keep-alive tunnel pool per (proxy, scheme) so R2 pack PUT/GET bursts reuse
// CONNECT tunnels instead of paying a proxy + TLS handshake for every pack.
const pooledProxyAgents = new Map<string, http.Agent>();

function agentForUrl(u: URL): http.Agent | undefined {
  const proxy = resolveProxyForUrl(u);
  if (!proxy) return undefined;
  const key = `${proxy.display}|${proxy.username ?? ""}|${u.protocol}`;
  let agent = pooledProxyAgents.get(key);
  if (!agent) {
    agent = selectTransportAgent(u, {}, { keepAlive: true });
    if (agent) pooledProxyAgents.set(key, agent);
  }
  return agent;
}

/** Drops pooled proxy tunnels (used by tests and when proxy env changes at runtime). */
export function resetHttpProxyAgents(): void {
  for (const agent of pooledProxyAgents.values()) agent.destroy();
  pooledProxyAgents.clear();
}

/**
 * Minimal buffered HTTP(S) client used for Coordinator REST and R2 presigned PUT/GET.
 * Unlike the global `fetch`, it honours `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY` /
 * `NO_PROXY` (HTTP CONNECT and SOCKS5).
 */
export function httpRequestBytes(
  method: "GET" | "PUT" | "POST",
  url: string,
  opts: {
    headers?: Record<string, string>;
    body?: Uint8Array;
    idleTimeoutMs?: number;
  } = {},
): Promise<HttpResponseBytes> {
  const u = new URL(url);
  const lib = u.protocol === "https:" ? https : http;
  const headers: Record<string, string> = { ...(opts.headers ?? {}) };
  if (opts.body && headers["content-length"] === undefined) {
    headers["content-length"] = String(opts.body.byteLength);
  }

  return new Promise<HttpResponseBytes>((resolve, reject) => {
    const req = lib.request(
      u,
      { method, headers, agent: agentForUrl(u) },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.once("error", reject);
        res.once("end", () => {
          resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks) });
        });
      },
    );
    req.setTimeout(opts.idleTimeoutMs ?? 120_000, () => {
      req.destroy(new Error(`HTTP ${method} ${u.host} idle timeout`));
    });
    req.once("error", reject);
    if (opts.body) {
      req.end(Buffer.from(opts.body.buffer, opts.body.byteOffset, opts.body.byteLength));
    } else {
      req.end();
    }
  });
}
