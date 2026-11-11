import { blake3 } from "@noble/hashes/blake3";
import { sha256 } from "@noble/hashes/sha256";
import { hmac } from "@noble/hashes/hmac";
import { hkdf } from "@noble/hashes/hkdf";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import { x25519 } from "@noble/curves/ed25519";

const encoder = new TextEncoder();

export function utf8Bytes(text: string): Uint8Array {
  return encoder.encode(text);
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error("Invalid hex length");
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new Error("Invalid hex character");
    }
    out[i] = byte;
  }
  return out;
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  let total = 0;
  for (const arr of arrays) total += arr.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const arr of arrays) {
    out.set(arr, offset);
    offset += arr.length;
  }
  return out;
}

export function randomBytes(length: number): Uint8Array {
  const buf = new Uint8Array(length);
  globalThis.crypto.getRandomValues(buf);
  return buf;
}

export function blake3Bytes(data: Uint8Array): Uint8Array {
  return blake3(data);
}

export function blake3Hex(data: Uint8Array): string {
  return bytesToHex(blake3(data));
}

export function sha256Bytes(data: Uint8Array): Uint8Array {
  return sha256(data);
}

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data));
}

export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return hmac(sha256, key, data);
}

export function hmacSha256Hex(key: Uint8Array, data: Uint8Array): string {
  return bytesToHex(hmacSha256(key, data));
}

export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

export function aeadEncrypt(
  key32: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const nonce = randomBytes(12);
  const cipher = chacha20poly1305(key32, nonce, aad);
  const sealed = cipher.encrypt(plaintext);
  return concatBytes(nonce, sealed);
}

/**
 * SIV-style deterministic convergent AEAD encryption for scoped CAS packs.
 * Identical compressed pack payloads under the same 256-bit scope CAS key
 * produce identical (nonce, ciphertext, tag) wire bytes and identical packId,
 * while distinct payloads derive cryptographically independent 96-bit nonces.
 */
export function aeadEncryptConvergent(
  key32: Uint8Array,
  plaintext: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  const digestBytes = utf8Bytes(blake3Hex(plaintext));
  const nonce = hmacSha256(
    key32,
    concatBytes(utf8Bytes("beamsync/siv/v1:"), aad ?? new Uint8Array(0), digestBytes),
  ).subarray(0, 12);
  const cipher = chacha20poly1305(key32, nonce, aad);
  const sealed = cipher.encrypt(plaintext);
  return concatBytes(nonce, sealed);
}

export function aeadDecrypt(
  key32: Uint8Array,
  sealedWithNonce: Uint8Array,
  aad?: Uint8Array,
): Uint8Array {
  if (sealedWithNonce.length < 28) {
    throw new Error("AEAD payload too short");
  }
  const nonce = sealedWithNonce.subarray(0, 12);
  const ciphertext = sealedWithNonce.subarray(12);
  const cipher = chacha20poly1305(key32, nonce, aad);
  return cipher.decrypt(ciphertext);
}

export interface SessionKeyMaterial {
  rootKey: Uint8Array;
  confirmKeySource: Uint8Array;
  confirmKeyTarget: Uint8Array;
  transportKey: Uint8Array;
  packKey: Uint8Array;
  hostFingerprintKey: Uint8Array;
}

export function deriveSessionKeyMaterial(
  masterSecret: Uint8Array,
  sessionId: string,
  transcriptContext = "",
): SessionKeyMaterial {
  const salt = utf8Bytes(`beamsync/v1/session:${sessionId}`);
  const rootKey = hkdf(sha256, masterSecret, salt, utf8Bytes(`root:${transcriptContext}`), 32);
  return {
    rootKey,
    confirmKeySource: hkdf(sha256, rootKey, salt, utf8Bytes("confirm:source"), 32),
    confirmKeyTarget: hkdf(sha256, rootKey, salt, utf8Bytes("confirm:target"), 32),
    transportKey: hkdf(sha256, rootKey, salt, utf8Bytes("transport:aead"), 32),
    packKey: hkdf(sha256, rootKey, salt, utf8Bytes("pack:aead"), 32),
    hostFingerprintKey: hkdf(sha256, rootKey, salt, utf8Bytes("host:fingerprint"), 32),
  };
}

export function computeHostFingerprint(
  hostFingerprintKey: Uint8Array,
  rawMachineId: string,
  rawBootId: string,
): string {
  return hmacSha256Hex(hostFingerprintKey, utf8Bytes(`${rawMachineId.trim()}:${rawBootId.trim()}`));
}

/**
 * Curve25519 Encrypted Key Exchange (EKE) PAKE participant.
 * Masks ephemeral X25519 public keys with a role-separated stream derived from
 * the pairing phrase without any offline-verifiable authentication tag, then
 * binds both masked public keys + password verifier into HKDF key derivation
 * and mutual HMAC confirmation.
 */
export class PakeHandshake {
  readonly role: "source" | "target";
  readonly sessionId: string;
  private readonly pwMaskSource: Uint8Array;
  private readonly pwMaskTarget: Uint8Array;
  private readonly pwVerifier: Uint8Array;
  private readonly privKey: Uint8Array;
  private readonly maskedPubHex: string;

  constructor(role: "source" | "target", sessionId: string, secretPhrase: string) {
    this.role = role;
    this.sessionId = sessionId;
    const normalizedSecret = secretPhrase.trim().toLowerCase();
    const salt = utf8Bytes(`beamsync/pake/v1:${sessionId}`);
    const pwPrk = hkdf(sha256, utf8Bytes(normalizedSecret), salt, utf8Bytes("pake-prk"), 32);
    this.pwMaskSource = hkdf(sha256, pwPrk, salt, utf8Bytes("mask:source"), 32);
    this.pwMaskTarget = hkdf(sha256, pwPrk, salt, utf8Bytes("mask:target"), 32);
    this.pwVerifier = hkdf(sha256, pwPrk, salt, utf8Bytes("verifier"), 32);

    this.privKey = x25519.utils.randomPrivateKey();
    const rawPub = x25519.getPublicKey(this.privKey);
    const myMask = role === "source" ? this.pwMaskSource : this.pwMaskTarget;
    const masked = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      masked[i] = rawPub[i] ^ myMask[i];
    }
    this.maskedPubHex = bytesToHex(masked);
  }

  getPublicMessage(): string {
    return this.maskedPubHex;
  }

  finish(peerMaskedPubHex: string): {
    keys: SessionKeyMaterial;
    myConfirmMacHex: string;
    expectedPeerConfirmMacHex: string;
  } {
    const peerMasked = hexToBytes(peerMaskedPubHex);
    if (peerMasked.length !== 32) {
      throw new Error("Invalid peer PAKE public message length");
    }
    const peerMask = this.role === "source" ? this.pwMaskTarget : this.pwMaskSource;
    const peerPub = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      peerPub[i] = peerMasked[i] ^ peerMask[i];
    }
    // Clamp MSB per RFC 7748 u-coordinate decoding so arbitrary 32-byte masked strings decode safely
    peerPub[31] &= 0x7f;

    const dhShared = x25519.getSharedSecret(this.privKey, peerPub);
    const sourceMsg = this.role === "source" ? this.maskedPubHex : peerMaskedPubHex;
    const targetMsg = this.role === "target" ? this.maskedPubHex : peerMaskedPubHex;
    const transcript = `${this.sessionId}:${sourceMsg}:${targetMsg}`;
    const ikm = concatBytes(dhShared, this.pwVerifier);
    const keys = deriveSessionKeyMaterial(ikm, this.sessionId, transcript);

    const transcriptBytes = utf8Bytes(`confirm:${transcript}`);
    const sourceMac = hmacSha256Hex(keys.confirmKeySource, transcriptBytes);
    const targetMac = hmacSha256Hex(keys.confirmKeyTarget, transcriptBytes);

    return {
      keys,
      myConfirmMacHex: this.role === "source" ? sourceMac : targetMac,
      expectedPeerConfirmMacHex: this.role === "source" ? targetMac : sourceMac,
    };
  }
}
