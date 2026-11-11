import crypto from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import path from "node:path";

function encodeDerLength(len: number): Buffer {
  if (len < 0x80) {
    return Buffer.from([len]);
  }
  const bytes: number[] = [];
  let n = len;
  while (n > 0) {
    bytes.unshift(n & 0xff);
    n >>>= 8;
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function derTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), encodeDerLength(content.length), content]);
}

function derSequence(items: Buffer[]): Buffer {
  return derTlv(0x30, Buffer.concat(items));
}

function derSet(items: Buffer[]): Buffer {
  return derTlv(0x31, Buffer.concat(items));
}

function derOid(oidBytes: number[]): Buffer {
  return derTlv(0x06, Buffer.from(oidBytes));
}

function derInteger(rawPositiveBytes: Buffer): Buffer {
  const needsLeadingZero = rawPositiveBytes.length === 0 || (rawPositiveBytes[0] & 0x80) !== 0;
  const body = needsLeadingZero
    ? Buffer.concat([Buffer.from([0x00]), rawPositiveBytes])
    : rawPositiveBytes;
  return derTlv(0x02, body);
}

function derBitString(content: Buffer, unusedBits = 0): Buffer {
  return derTlv(0x03, Buffer.concat([Buffer.from([unusedBits]), content]));
}

function derOctetString(content: Buffer): Buffer {
  return derTlv(0x04, content);
}

function derUtf8String(str: string): Buffer {
  return derTlv(0x0c, Buffer.from(str, "utf8"));
}

function derGeneralizedTime(date: Date): Buffer {
  // YYYYMMDDHHMMSSZ
  const iso = date.toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z";
  return derTlv(0x18, Buffer.from(iso, "ascii"));
}

function toPem(label: string, der: Buffer): string {
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,64}/g) ?? [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----\n`;
}

export interface SelfSignedTlsMaterial {
  certPem: string;
  keyPem: string;
  certSha256: string;
}

/**
 * Generates (or loads from disk) a pure Node `node:crypto` X.509v3 ECDSA P-256
 * self-signed TLS certificate for IP-only / domainless DERP Edge Relay deployments
 * (e.g. Shanghai / domestic cloud VMs without ICP domain filing).
 * Requires zero external `openssl` CLI binary or CA infrastructure.
 */
export async function getOrCreateSelfSignedTlsMaterial(options?: {
  commonName?: string;
  ipSan?: string;
  cacheFilePath?: string;
  validityDays?: number;
}): Promise<SelfSignedTlsMaterial> {
  if (options?.cacheFilePath) {
    try {
      const raw = JSON.parse(await readFile(options.cacheFilePath, "utf8")) as {
        certPem: string;
        keyPem: string;
      };
      const x509 = new crypto.X509Certificate(raw.certPem);
      const certSha256 = crypto
        .createHash("sha256")
        .update(x509.raw)
        .digest("hex");
      return {
        certPem: raw.certPem,
        keyPem: raw.keyPem,
        certSha256,
      };
    } catch {
      // Cache file does not exist yet; generate fresh keypair & cert below
    }
  }

  const { publicKey, privateKey } = crypto.generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });

  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  const keyPem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;

  // ecdsa-with-SHA256 OID: 1.2.840.10045.4.3.2 -> 2a 86 48 ce 3d 04 03 02
  const sigAlgSeq = derSequence([
    derOid([0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]),
  ]);

  // Subject / Issuer CN (OID 2.5.4.3 -> 55 04 03)
  const cn = options?.commonName ?? "beamsync-derp-ip-node";
  const rdnCn = derSet([
    derSequence([derOid([0x55, 0x04, 0x03]), derUtf8String(cn)]),
  ]);
  const nameSeq = derSequence([rdnCn]);

  const now = Date.now();
  const notBefore = new Date(now - 60 * 60 * 1000);
  const notAfter = new Date(
    now + (options?.validityDays ?? 3650) * 24 * 60 * 60 * 1000,
  );
  const validitySeq = derSequence([
    derGeneralizedTime(notBefore),
    derGeneralizedTime(notAfter),
  ]);

  // Extensions: BasicConstraints (CA:FALSE) + optional IPv4 SAN
  const extItems: Buffer[] = [
    // BasicConstraints OID 2.5.29.19 -> 55 1d 13, empty SEQUENCE = CA:FALSE
    derSequence([
      derOid([0x55, 0x1d, 0x13]),
      derOctetString(derSequence([])),
    ]),
  ];

  if (options?.ipSan) {
    const ipParts = options.ipSan.split(".").map((x) => Number.parseInt(x, 10));
    if (ipParts.length === 4 && ipParts.every((n) => n >= 0 && n <= 255)) {
      // SubjectAltName OID 2.5.29.17 -> 55 1d 11; GeneralName iPAddress [7] IMPLICIT OCTET STRING (tag 0x87)
      const ipGeneralName = derTlv(0x87, Buffer.from(ipParts));
      extItems.push(
        derSequence([
          derOid([0x55, 0x1d, 0x11]),
          derOctetString(derSequence([ipGeneralName])),
        ]),
      );
    }
  }

  const explicitVersionV3 = derTlv(0xa0, derInteger(Buffer.from([0x02])));
  const explicitExtensions = derTlv(0xa3, derSequence(extItems));
  const serialBytes = crypto.randomBytes(16);
  serialBytes[0] &= 0x7f;
  if (serialBytes[0] === 0) serialBytes[0] = 0x01;

  const tbsCertificate = derSequence([
    explicitVersionV3,
    derInteger(serialBytes),
    sigAlgSeq,
    nameSeq,
    validitySeq,
    nameSeq,
    spkiDer,
    explicitExtensions,
  ]);

  const signatureDer = crypto.sign("sha256", tbsCertificate, privateKey);
  const certDer = derSequence([
    tbsCertificate,
    sigAlgSeq,
    derBitString(signatureDer, 0),
  ]);

  const certPem = toPem("CERTIFICATE", certDer);
  // Validate immediately using Node's native OpenSSL X509 parser
  const parsedX509 = new crypto.X509Certificate(certPem);
  const certSha256 = crypto
    .createHash("sha256")
    .update(parsedX509.raw)
    .digest("hex");

  if (options?.cacheFilePath) {
    await mkdir(path.dirname(options.cacheFilePath), { recursive: true });
    await writeFile(
      options.cacheFilePath,
      JSON.stringify({ certPem, keyPem }, null, 2),
      { mode: 0o600 },
    );
  }

  return { certPem, keyPem, certSha256 };
}

export function computeCertPemSha256(certPem: string): string {
  const x509 = new crypto.X509Certificate(certPem);
  return crypto.createHash("sha256").update(x509.raw).digest("hex");
}
