import { createHash } from "node:crypto";
import type http from "node:http";
import type { Duplex } from "node:stream";

/**
 * Server-side WebSocket endpoint that hands message payloads to the caller while they
 * arrive instead of collecting a whole message first.
 *
 * The Edge Relay only moves bytes between two peers. Reassembling an 8 MiB message before
 * forwarding it costs memory per active transfer; this endpoint forwards each received
 * piece as one WebSocket fragment, so the relay holds at most the socket buffers.
 * Fragmentation is invisible to WebSocket clients: they still receive one message.
 */

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

const OPCODE_CONTINUATION = 0x0;
const OPCODE_TEXT = 0x1;
const OPCODE_BINARY = 0x2;
const OPCODE_CLOSE = 0x8;
const OPCODE_PING = 0x9;
const OPCODE_PONG = 0xa;

const MAX_HEADER_BYTES = 14;
const CLOSE_LINGER_MS = 3_000;
const EMPTY = Buffer.alloc(0);

export type WsDataOpcode = typeof OPCODE_TEXT | typeof OPCODE_BINARY;

export interface WsStreamHandlers {
  /**
   * One piece of a data message. `first` marks the first piece of a message and `fin` the
   * last one; a small message arrives as a single piece with both set. `payload` is only
   * valid to keep if the callee does not need the bytes to stay unchanged elsewhere.
   */
  onFragment(payload: Buffer, first: boolean, fin: boolean, opcode: WsDataOpcode): void;
  /** Called exactly once when the connection stops being usable. */
  onClose(code: number, reason: string): void;
}

export interface WsStreamOptions {
  /** Largest accepted message in bytes (sum of all its fragments). */
  maxMessageBytes: number;
}

/**
 * Validates the upgrade request and writes the `101 Switching Protocols` response.
 * Returns false (after answering `400`) if the request is not a WebSocket version 13 upgrade.
 * No extension or subprotocol is negotiated.
 */
export function acceptWebSocketUpgrade(req: http.IncomingMessage, socket: Duplex): boolean {
  const key = req.headers["sec-websocket-key"];
  const upgrade = req.headers.upgrade;
  const version = req.headers["sec-websocket-version"];
  if (
    req.method !== "GET" ||
    typeof upgrade !== "string" ||
    upgrade.toLowerCase() !== "websocket" ||
    typeof key !== "string" ||
    !/^[+/0-9A-Za-z]{22}==$/.test(key) ||
    version !== "13"
  ) {
    socket.write(
      "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nSec-WebSocket-Version: 13\r\n\r\n",
    );
    socket.destroy();
    return false;
  }
  const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
  );
  return true;
}

const maskScratch8 = new Uint8Array(4);
const maskScratch32 = new Uint32Array(maskScratch8.buffer);

/** XORs `buf` in place with the 4-byte `mask`, starting at mask position `maskPos`. */
export function unmaskInPlace(buf: Buffer, mask: Uint8Array, maskPos: number): void {
  const len = buf.length;
  let i = 0;
  let m = maskPos & 3;
  while (i < len && ((buf.byteOffset + i) & 3) !== 0) {
    buf[i] ^= mask[m];
    m = (m + 1) & 3;
    i++;
  }
  const words = (len - i) >>> 2;
  if (words > 0) {
    maskScratch8[0] = mask[m];
    maskScratch8[1] = mask[(m + 1) & 3];
    maskScratch8[2] = mask[(m + 2) & 3];
    maskScratch8[3] = mask[(m + 3) & 3];
    const word = maskScratch32[0];
    const view = new Uint32Array(buf.buffer, buf.byteOffset + i, words);
    for (let j = 0; j < words; j++) {
      view[j] ^= word;
    }
    i += words << 2;
  }
  while (i < len) {
    buf[i] ^= mask[m];
    m = (m + 1) & 3;
    i++;
  }
}

function encodeFrameHeader(opcode: number, fin: boolean, payloadLength: number): Buffer {
  const first = (fin ? 0x80 : 0x00) | opcode;
  if (payloadLength < 126) {
    return Buffer.from([first, payloadLength]);
  }
  if (payloadLength < 65536) {
    const header = Buffer.allocUnsafe(4);
    header[0] = first;
    header[1] = 126;
    header.writeUInt16BE(payloadLength, 2);
    return header;
  }
  const header = Buffer.allocUnsafe(10);
  header[0] = first;
  header[1] = 127;
  header.writeUInt32BE(Math.floor(payloadLength / 0x1_0000_0000), 2);
  header.writeUInt32BE(payloadLength >>> 0, 6);
  return header;
}

export class WsStreamConnection {
  private readonly socket: Duplex;
  private readonly handlers: WsStreamHandlers;
  private readonly maxMessageBytes: number;

  // Inbound frame parser
  private readonly headerBuf = Buffer.allocUnsafe(MAX_HEADER_BYTES);
  private headerFill = 0;
  private headerNeed = 2;
  private inPayload = false;
  private frameOpcode = 0;
  private frameFin = false;
  private frameRemaining = 0;
  private frameMaskPos = 0;
  private readonly frameMask = new Uint8Array(4);
  private controlPayload: Buffer | null = null;
  private controlFill = 0;
  /** Opcode of the data message whose fragments are still arriving, or 0 between messages. */
  private messageOpcode = 0;
  private messageFirstPending = false;
  private messageBytes = 0;

  // Outbound
  private outboundFragmented = false;
  private readonly drainWaiters: Array<() => void> = [];

  private closeFrameSent = false;
  private closed = false;
  private lingerTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(
    socket: Duplex,
    head: Buffer,
    handlers: WsStreamHandlers,
    options: WsStreamOptions,
  ) {
    this.socket = socket;
    this.handlers = handlers;
    this.maxMessageBytes = options.maxMessageBytes;

    const plain = socket as Duplex & {
      setTimeout?: (ms: number) => void;
      setNoDelay?: (on: boolean) => void;
    };
    plain.setTimeout?.(0);
    plain.setNoDelay?.(true);

    socket.on("data", (chunk: Buffer) => this.consume(chunk));
    socket.on("drain", () => this.runDrainWaiters());
    socket.on("end", () => {
      this.markClosed(1006, "");
      socket.end();
    });
    socket.on("error", () => {
      this.markClosed(1006, "");
      socket.destroy();
    });
    socket.on("close", () => {
      this.markClosed(1006, "");
      if (this.lingerTimer) {
        clearTimeout(this.lingerTimer);
        this.lingerTimer = null;
      }
    });

    if (head.length > 0) {
      this.consume(head);
    }
  }

  /** True until either side starts closing the connection. */
  get isOpen(): boolean {
    return !this.closed && !this.socket.destroyed;
  }

  /** Bytes accepted for sending that the socket has not written yet. */
  get bufferedBytes(): number {
    return this.socket.writableLength;
  }

  /** True while a fragmented message written to this connection has not been finished. */
  get hasUnfinishedOutboundMessage(): boolean {
    return this.outboundFragmented;
  }

  pauseReading(): void {
    this.socket.pause();
  }

  resumeReading(): void {
    this.socket.resume();
  }

  /**
   * Runs `fn` once the outbound buffer is flushed or the connection is gone.
   * Returns false, without keeping `fn`, when the socket has nothing left to flush.
   */
  onceDrained(fn: () => void): boolean {
    if (!this.isOpen || !this.socket.writableNeedDrain) {
      return false;
    }
    this.drainWaiters.push(fn);
    return true;
  }

  /**
   * Writes one piece of a data message. The first piece of a message carries the message
   * opcode, later ones are continuation frames; `fin` ends the message.
   */
  writeFragment(payload: Buffer, opcode: WsDataOpcode, first: boolean, fin: boolean): void {
    if (!this.isOpen) return;
    this.writeFrame(first ? opcode : OPCODE_CONTINUATION, fin, payload);
    this.outboundFragmented = !fin;
  }

  /** Sends one complete binary message. Must not be called while a fragmented message is unfinished. */
  sendBinaryMessage(payload: Buffer): void {
    if (!this.isOpen) return;
    if (this.outboundFragmented) {
      throw new Error("Cannot start a message inside an unfinished fragmented message");
    }
    this.writeFrame(OPCODE_BINARY, true, payload);
  }

  ping(): void {
    if (!this.isOpen) return;
    this.writeFrame(OPCODE_PING, true, EMPTY);
  }

  /** Starts the closing handshake: sends a close frame after everything already queued. */
  close(code: number, reason: string): void {
    if (this.closed) return;
    this.sendCloseFrame(code, reason);
    this.markClosed(code, reason);
    this.endSocketSoon();
  }

  /** Drops the connection without a closing handshake. */
  terminate(): void {
    this.markClosed(1006, "");
    this.socket.destroy();
  }

  private writeFrame(opcode: number, fin: boolean, payload: Buffer): void {
    const socket = this.socket;
    if (socket.destroyed || socket.writableEnded) return;
    const header = encodeFrameHeader(opcode, fin, payload.length);
    if (payload.length === 0) {
      socket.write(header);
      return;
    }
    socket.cork();
    socket.write(header);
    socket.write(payload);
    socket.uncork();
  }

  private sendCloseFrame(code: number, reason: string): void {
    if (this.closeFrameSent) return;
    this.closeFrameSent = true;
    const reasonBytes = Buffer.from(reason, "utf8").subarray(0, 123);
    const payload = Buffer.allocUnsafe(2 + reasonBytes.length);
    payload.writeUInt16BE(code, 0);
    reasonBytes.copy(payload, 2);
    this.writeFrame(OPCODE_CLOSE, true, payload);
  }

  private endSocketSoon(): void {
    const socket = this.socket;
    if (socket.destroyed) return;
    if (!socket.writableEnded) {
      socket.end();
    }
    if (!this.lingerTimer) {
      this.lingerTimer = setTimeout(() => socket.destroy(), CLOSE_LINGER_MS);
      this.lingerTimer.unref();
    }
  }

  private markClosed(code: number, reason: string): void {
    if (this.closed) return;
    this.closed = true;
    // A reader paused for backpressure would never observe the end of the stream.
    this.socket.resume();
    this.runDrainWaiters();
    this.handlers.onClose(code, reason);
  }

  private runDrainWaiters(): void {
    if (this.drainWaiters.length === 0) return;
    const waiters = this.drainWaiters.splice(0, this.drainWaiters.length);
    for (const fn of waiters) {
      fn();
    }
  }

  private fail(code: number, reason: string): void {
    this.close(code, reason);
  }

  private consume(chunk: Buffer): void {
    let offset = 0;
    const end = chunk.length;

    while (offset < end && !this.closed) {
      if (!this.inPayload) {
        // Collect the frame header; its length is known only after the second byte.
        while (this.headerFill < this.headerNeed && offset < end) {
          this.headerBuf[this.headerFill++] = chunk[offset++];
          if (this.headerFill === 2) {
            if ((this.headerBuf[1] & 0x80) === 0) {
              // Clients must mask every frame; without the bit there is no mask key to wait for.
              this.fail(1002, "unmasked_client_frame");
              return;
            }
            const lenCode = this.headerBuf[1] & 0x7f;
            this.headerNeed = 2 + (lenCode === 126 ? 2 : lenCode === 127 ? 8 : 0) + 4;
          }
        }
        if (this.headerFill < this.headerNeed) return;
        if (!this.beginFrame()) return;
        if (this.frameRemaining > 0) continue;
        // Zero-length frame: finish it without waiting for more bytes.
        this.deliverPayload(EMPTY);
        continue;
      }

      const take = Math.min(this.frameRemaining, end - offset);
      const piece = chunk.subarray(offset, offset + take);
      offset += take;
      unmaskInPlace(piece, this.frameMask, this.frameMaskPos);
      this.frameMaskPos = (this.frameMaskPos + take) & 3;
      this.frameRemaining -= take;
      this.deliverPayload(piece);
    }
  }

  /** Parses the collected header. Returns false if the connection was failed. */
  private beginFrame(): boolean {
    const b0 = this.headerBuf[0];
    const b1 = this.headerBuf[1];
    this.headerFill = 0;
    const need = this.headerNeed;
    this.headerNeed = 2;

    if ((b0 & 0x70) !== 0) {
      this.fail(1002, "reserved_bits_set");
      return false;
    }

    const opcode = b0 & 0x0f;
    const fin = (b0 & 0x80) !== 0;
    const lenCode = b1 & 0x7f;
    let length: number;
    if (lenCode < 126) {
      length = lenCode;
    } else if (lenCode === 126) {
      length = this.headerBuf.readUInt16BE(2);
    } else {
      const high = this.headerBuf.readUInt32BE(2);
      if (high > 0x1f_ffff) {
        this.fail(1009, "frame_too_large");
        return false;
      }
      length = high * 0x1_0000_0000 + this.headerBuf.readUInt32BE(6);
    }
    this.headerBuf.copy(this.frameMask, 0, need - 4, need);
    this.frameMaskPos = 0;

    if (opcode >= 0x8) {
      if (!fin || length > 125) {
        this.fail(1002, "invalid_control_frame");
        return false;
      }
      if (opcode !== OPCODE_CLOSE && opcode !== OPCODE_PING && opcode !== OPCODE_PONG) {
        this.fail(1002, "unknown_opcode");
        return false;
      }
      this.controlPayload = Buffer.allocUnsafe(length);
      this.controlFill = 0;
    } else if (opcode === OPCODE_CONTINUATION) {
      if (this.messageOpcode === 0) {
        this.fail(1002, "unexpected_continuation");
        return false;
      }
    } else if (opcode === OPCODE_TEXT || opcode === OPCODE_BINARY) {
      if (this.messageOpcode !== 0) {
        this.fail(1002, "expected_continuation");
        return false;
      }
      this.messageOpcode = opcode;
      this.messageFirstPending = true;
      this.messageBytes = 0;
    } else {
      this.fail(1002, "unknown_opcode");
      return false;
    }

    if (opcode < 0x8) {
      this.messageBytes += length;
      if (this.messageBytes > this.maxMessageBytes) {
        this.fail(1009, "message_too_large");
        return false;
      }
    }

    this.frameOpcode = opcode;
    this.frameFin = fin;
    this.frameRemaining = length;
    this.inPayload = true;
    return true;
  }

  private deliverPayload(piece: Buffer): void {
    const frameDone = this.frameRemaining === 0;

    if (this.frameOpcode >= 0x8) {
      const control = this.controlPayload!;
      piece.copy(control, this.controlFill);
      this.controlFill += piece.length;
      if (!frameDone) return;
      this.inPayload = false;
      this.controlPayload = null;
      this.handleControl(this.frameOpcode, control);
      return;
    }

    const fin = frameDone && this.frameFin;
    if (frameDone) {
      this.inPayload = false;
    }
    // An empty piece carries no data; it only matters when it ends the message.
    if (piece.length === 0 && !fin) return;

    const first = this.messageFirstPending;
    this.messageFirstPending = false;
    const opcode = this.messageOpcode as WsDataOpcode;
    if (fin) {
      this.messageOpcode = 0;
    }
    this.handlers.onFragment(piece, first, fin, opcode);
  }

  private handleControl(opcode: number, payload: Buffer): void {
    if (opcode === OPCODE_PING) {
      this.writeFrame(OPCODE_PONG, true, payload);
      return;
    }
    if (opcode === OPCODE_PONG) {
      return;
    }
    // Close frame: answer with the same status code, then stop.
    let code = 1005;
    let reason = "";
    if (payload.length === 1) {
      this.fail(1002, "invalid_close_payload");
      return;
    }
    if (payload.length >= 2) {
      code = payload.readUInt16BE(0);
      reason = payload.subarray(2).toString("utf8");
    }
    if (!this.closeFrameSent) {
      this.closeFrameSent = true;
      this.writeFrame(OPCODE_CLOSE, true, payload.length >= 2 ? payload.subarray(0, 2) : EMPTY);
    }
    this.markClosed(code, reason);
    this.endSocketSoon();
  }
}
