import {
  hmacSha256Hex,
  presignR2Url,
  utf8Bytes,
} from "@beamsync/protocol";

export interface PackStorageDriver {
  readonly mode: "r2-presigned" | "builtin-http";
  mintPutUrl(storageKey: string, expiresInSeconds?: number): Promise<string>;
  mintGetUrl(storageKey: string, expiresInSeconds?: number): Promise<string>;
  deleteObjects?(storageKeys: string[]): Promise<void>;
}

export interface R2StorageConfig {
  accountId?: string;
  endpoint?: string; // Overrides https://<accountId>.r2.cloudflarestorage.com if custom S3/R2 endpoint is desired
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
  region?: string;
}

export class R2PresignedStorageDriver implements PackStorageDriver {
  readonly mode = "r2-presigned" as const;
  private readonly endpoint: string;
  private readonly bucket: string;
  private readonly accessKeyId: string;
  private readonly secretAccessKey: string;
  private readonly region: string;

  constructor(config: R2StorageConfig) {
    const resolvedEndpoint =
      config.endpoint ??
      (config.accountId
        ? `https://${config.accountId}.r2.cloudflarestorage.com`
        : "");
    if (!resolvedEndpoint) {
      throw new Error(
        "R2PresignedStorageDriver requires either accountId or endpoint",
      );
    }
    this.endpoint = resolvedEndpoint.replace(/\/+$/, "");
    this.bucket = config.bucket;
    this.accessKeyId = config.accessKeyId;
    this.secretAccessKey = config.secretAccessKey;
    this.region = config.region ?? "auto";
  }

  async mintPutUrl(storageKey: string, expiresInSeconds = 3600): Promise<string> {
    return presignR2Url({
      method: "PUT",
      endpoint: this.endpoint,
      bucket: this.bucket,
      key: storageKey,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.secretAccessKey,
      region: this.region,
      expiresInSeconds,
    });
  }

  async mintGetUrl(storageKey: string, expiresInSeconds = 3600): Promise<string> {
    return presignR2Url({
      method: "GET",
      endpoint: this.endpoint,
      bucket: this.bucket,
      key: storageKey,
      accessKeyId: this.accessKeyId,
      secretAccessKey: this.secretAccessKey,
      region: this.region,
      expiresInSeconds,
    });
  }

  async deleteObjects(storageKeys: string[]): Promise<void> {
    await Promise.allSettled(
      storageKeys.map(async (key) => {
        const delUrl = presignR2Url({
          method: "DELETE",
          endpoint: this.endpoint,
          bucket: this.bucket,
          key,
          accessKeyId: this.accessKeyId,
          secretAccessKey: this.secretAccessKey,
          region: this.region,
          expiresInSeconds: 300,
        });
        await fetch(delUrl, { method: "DELETE" });
      }),
    );
  }
}

export interface SignedHttpDriverOptions {
  publicBaseUrl: string;
  signingSecret: Uint8Array;
  onDeleteObjects?: (storageKeys: string[]) => Promise<void>;
}

export function signHttpObjectToken(
  signingSecret: Uint8Array,
  method: "PUT" | "GET",
  storageKey: string,
  expiresAtMs: number,
): string {
  const payload = `${method}:${expiresAtMs}:${storageKey}`;
  return hmacSha256Hex(signingSecret, utf8Bytes(payload));
}

export class SignedHttpStorageDriver implements PackStorageDriver {
  readonly mode = "builtin-http" as const;
  private publicBaseUrl: string;
  private readonly signingSecret: Uint8Array;
  private readonly onDeleteObjects?: (storageKeys: string[]) => Promise<void>;

  constructor(options: SignedHttpDriverOptions) {
    this.publicBaseUrl = options.publicBaseUrl.replace(/\/+$/, "");
    this.signingSecret = options.signingSecret;
    this.onDeleteObjects = options.onDeleteObjects;
  }

  setPublicBaseUrl(baseUrl: string): void {
    this.publicBaseUrl = baseUrl.replace(/\/+$/, "");
  }

  async mintPutUrl(storageKey: string, expiresInSeconds = 3600): Promise<string> {
    const exp = Date.now() + expiresInSeconds * 1000;
    const sig = signHttpObjectToken(this.signingSecret, "PUT", storageKey, exp);
    const encodedKey = encodeURIComponent(storageKey);
    return `${this.publicBaseUrl}/v1/packs/${encodedKey}?exp=${exp}&sig=${sig}`;
  }

  async mintGetUrl(storageKey: string, expiresInSeconds = 3600): Promise<string> {
    const exp = Date.now() + expiresInSeconds * 1000;
    const sig = signHttpObjectToken(this.signingSecret, "GET", storageKey, exp);
    const encodedKey = encodeURIComponent(storageKey);
    return `${this.publicBaseUrl}/v1/packs/${encodedKey}?exp=${exp}&sig=${sig}`;
  }

  async deleteObjects(storageKeys: string[]): Promise<void> {
    if (this.onDeleteObjects) {
      await this.onDeleteObjects(storageKeys);
    }
  }
}
