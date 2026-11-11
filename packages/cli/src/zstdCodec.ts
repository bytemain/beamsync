import { compress, decompress } from "@mongodb-js/zstd";
import { decompress as fzstdDecompress } from "fzstd";

export async function zstdCompress(
  raw: Uint8Array,
  level = 3,
): Promise<Uint8Array> {
  const buf = Buffer.from(raw.buffer, raw.byteOffset, raw.byteLength);
  const out = await compress(buf, level);
  return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
}

export async function zstdDecompress(
  compressed: Uint8Array,
): Promise<Uint8Array> {
  try {
    const buf = Buffer.from(
      compressed.buffer,
      compressed.byteOffset,
      compressed.byteLength,
    );
    const out = await decompress(buf);
    return new Uint8Array(out.buffer, out.byteOffset, out.byteLength);
  } catch {
    return fzstdDecompress(compressed);
  }
}
