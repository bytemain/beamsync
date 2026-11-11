import { hmacSha256, sha256Hex, bytesToHex, utf8Bytes } from "./crypto.js";

export interface SigV4PresignInput {
  method: "GET" | "PUT" | "HEAD" | "DELETE";
  endpoint: string; // e.g. https://<accountId>.r2.cloudflarestorage.com
  bucket: string;
  key: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string; // defaults to "auto" for Cloudflare R2
  expiresInSeconds?: number; // 1..604800
  now?: Date;
}

function encodeRfc3986(str: string): string {
  return encodeURIComponent(str).replace(
    /[!'()*]/g,
    (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`,
  );
}

function formatAmzDate(date: Date): { amzDate: string; dateStamp: string } {
  const iso = date.toISOString().replace(/[:-]|\.\d{3}/g, "");
  return {
    amzDate: iso,
    dateStamp: iso.slice(0, 8),
  };
}

/**
 * Pure offline AWS Signature Version 4 URL presigner compatible with Cloudflare R2
 * (`region = "auto"`, `service = "s3"`). Runs in both Cloudflare Workers and Node.js.
 */
export function presignR2Url(input: SigV4PresignInput): string {
  const region = input.region ?? "auto";
  const expires = Math.max(1, Math.min(604_800, input.expiresInSeconds ?? 3600));
  const now = input.now ?? new Date();
  const { amzDate, dateStamp } = formatAmzDate(now);

  const baseUrl = new URL(input.endpoint);
  const host = baseUrl.host;
  const encodedKeySegments = input.key
    .split("/")
    .filter((s) => s.length > 0)
    .map(encodeRfc3986)
    .join("/");
  const canonicalUri = `/${encodeRfc3986(input.bucket)}/${encodedKeySegments}`;

  const credentialScope = `${dateStamp}/${region}/s3/aws4_request`;
  const queryParams: Array<[string, string]> = [
    ["X-Amz-Algorithm", "AWS4-HMAC-SHA256"],
    ["X-Amz-Credential", `${input.accessKeyId}/${credentialScope}`],
    ["X-Amz-Date", amzDate],
    ["X-Amz-Expires", String(expires)],
    ["X-Amz-SignedHeaders", "host"],
  ];

  queryParams.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  const canonicalQueryString = queryParams
    .map(([k, v]) => `${encodeRfc3986(k)}=${encodeRfc3986(v)}`)
    .join("&");

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = "host";
  const payloadHash = "UNSIGNED-PAYLOAD";

  const canonicalRequest = [
    input.method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    sha256Hex(utf8Bytes(canonicalRequest)),
  ].join("\n");

  const kDate = hmacSha256(utf8Bytes(`AWS4${input.secretAccessKey}`), utf8Bytes(dateStamp));
  const kRegion = hmacSha256(kDate, utf8Bytes(region));
  const kService = hmacSha256(kRegion, utf8Bytes("s3"));
  const kSigning = hmacSha256(kService, utf8Bytes("aws4_request"));
  const signature = bytesToHex(hmacSha256(kSigning, utf8Bytes(stringToSign)));

  return `${baseUrl.protocol}//${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}
