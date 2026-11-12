import {
  CONTROL_STREAM_WINDOW_SEGMENTS,
  ControlStreamLineSplitter,
  openControlStreamSegment,
  sealControlStreamSegment,
  type ClientToServerWsMessage,
  type ControlStreamName,
  type ServerToClientWsMessage,
} from "@beamsync/protocol";
import { zstdCompress, zstdDecompress } from "./zstdCodec.js";

/** The part of the signaling client a control stream needs. */
export interface ControlStreamSignaling {
  send(msg: ClientToServerWsMessage): void;
  subscribe(fn: (msg: ServerToClientWsMessage) => void): () => void;
}

export interface ControlStreamStats {
  segments: number;
  records: number;
  rawBytes: number;
  /** Sealed bytes before base64 encoding. */
  sealedBytes: number;
}

export interface ControlStreamEndpoint {
  sig: ControlStreamSignaling;
  stream: ControlStreamName;
  controlKey: Uint8Array;
  sessionId: string;
}

/**
 * Writes newline-delimited records as a sealed control stream.
 *
 * Records are packed into fixed-size segments regardless of record boundaries, so neither the
 * number of records nor the size of a single record is limited by the signaling message size.
 * At most `windowSegments` segments are in flight: the writer then waits for the reader's
 * acknowledgement, which keeps the Coordinator from ever buffering more than the window.
 */
export async function writeControlStream(
  params: ControlStreamEndpoint & {
    records: Iterable<string>;
    segmentBytes: number;
    windowSegments?: number;
  },
): Promise<ControlStreamStats> {
  const { sig, stream, controlKey, sessionId, segmentBytes } = params;
  const windowSegments = Math.max(1, params.windowSegments ?? CONTROL_STREAM_WINDOW_SEGMENTS);
  if (!Number.isSafeInteger(segmentBytes) || segmentBytes < 1) {
    throw new Error(`Invalid control stream segment size ${segmentBytes}`);
  }

  const stats: ControlStreamStats = { segments: 0, records: 0, rawBytes: 0, sealedBytes: 0 };
  let nextIndex = 0;
  let ackedIndex = -1;
  let failure = null as Error | null;
  let wake = null as (() => void) | null;

  const unsubscribe = sig.subscribe((msg) => {
    if (msg.type === "session_error") {
      failure = new Error(`${msg.code}: ${msg.message}`);
    } else if (msg.type === "control_stream_ack" && msg.stream === stream) {
      if (msg.index >= nextIndex) {
        failure = new Error(
          `CONTROL_STREAM_INTEGRITY: "${stream}" acknowledgement for segment ${msg.index}, which was never sent`,
        );
      } else {
        ackedIndex = Math.max(ackedIndex, msg.index);
      }
    } else {
      return;
    }
    wake?.();
  });

  const emit = async (raw: Uint8Array, final: boolean): Promise<void> => {
    while (!failure && nextIndex - (ackedIndex + 1) >= windowSegments) {
      await new Promise<void>((resolve) => {
        wake = resolve;
      });
      wake = null;
    }
    if (failure) throw failure;
    const index = nextIndex;
    const sealed = await sealControlStreamSegment(
      { controlKey, sessionId, stream, index, final },
      raw,
      zstdCompress,
    );
    if (failure) throw failure;
    nextIndex++;
    stats.segments++;
    stats.rawBytes += raw.byteLength;
    stats.sealedBytes += sealed.byteLength;
    sig.send({
      type: "control_stream_chunk",
      stream,
      index,
      final,
      payloadBase64: Buffer.from(sealed.buffer, sealed.byteOffset, sealed.byteLength).toString(
        "base64",
      ),
    });
  };

  let carry: Buffer = Buffer.alloc(0);
  let batch: string[] = [];
  let batchChars = 0;

  const flush = async (last: boolean): Promise<void> => {
    let buf = carry;
    if (batch.length > 0) {
      const encoded = Buffer.from(`${batch.join("\n")}\n`, "utf8");
      buf = carry.byteLength > 0 ? Buffer.concat([carry, encoded]) : encoded;
      batch = [];
      batchChars = 0;
    }
    let offset = 0;
    // Up to one full segment is held back so the last flush always has the final segment
    // to send (empty only when the stream itself is empty)
    while (buf.byteLength - offset > segmentBytes) {
      await emit(buf.subarray(offset, offset + segmentBytes), false);
      offset += segmentBytes;
    }
    if (last) {
      await emit(buf.subarray(offset), true);
      carry = Buffer.alloc(0);
    } else {
      carry = buf.subarray(offset);
    }
  };

  try {
    for (const record of params.records) {
      if (record.includes("\n")) {
        throw new Error("Control stream records must not contain a newline");
      }
      batch.push(record);
      batchChars += record.length + 1;
      stats.records++;
      // A character is at least one byte, so this never under-fills by more than one batch
      if (batchChars >= segmentBytes) {
        await flush(false);
      }
    }
    await flush(true);
    return stats;
  } finally {
    unsubscribe();
  }
}

/**
 * Reads a sealed control stream, calling `onRecord` for each record in order.
 *
 * Must be started before the peer can begin writing. Segments are authenticated against their
 * position, so anything other than the exact sequence the writer produced rejects `done`.
 */
export function readControlStream(
  params: ControlStreamEndpoint & { onRecord: (record: string) => void },
): {
  done: Promise<ControlStreamStats>;
  /**
   * Call when a later message proves the writer has finished: once the segments received so
   * far are processed, a stream without its final segment rejects `done` instead of waiting.
   */
  expectComplete: () => void;
  cancel: () => void;
} {
  const { sig, stream, controlKey, sessionId, onRecord } = params;
  const stats: ControlStreamStats = { segments: 0, records: 0, rawBytes: 0, sealedBytes: 0 };
  const splitter = new ControlStreamLineSplitter();
  let expectedIndex = 0;
  let settled = false;
  let chain: Promise<void> = Promise.resolve();
  let resolveDone!: (stats: ControlStreamStats) => void;
  let rejectDone!: (err: Error) => void;
  const done = new Promise<ControlStreamStats>((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });

  const settle = (err: Error | null): void => {
    if (settled) return;
    settled = true;
    unsubscribe();
    if (err) rejectDone(err);
    else resolveDone(stats);
  };

  const handleSegment = async (
    msg: Extract<ServerToClientWsMessage, { type: "control_stream_chunk" }>,
  ): Promise<void> => {
    if (settled) return;
    if (msg.index !== expectedIndex) {
      throw new Error(
        `CONTROL_STREAM_INTEGRITY: expected segment ${expectedIndex} of "${stream}", received ${msg.index}`,
      );
    }
    const sealed = Buffer.from(msg.payloadBase64, "base64");
    const raw = await openControlStreamSegment(
      { controlKey, sessionId, stream, index: msg.index, final: msg.final },
      sealed,
      zstdDecompress,
    );
    if (settled) return;
    expectedIndex++;
    stats.segments++;
    stats.rawBytes += raw.byteLength;
    stats.sealedBytes += sealed.byteLength;
    splitter.push(raw, (line) => {
      stats.records++;
      onRecord(line);
    });
    if (msg.final) {
      splitter.finish();
    }
    sig.send({ type: "control_stream_ack", stream, index: msg.index });
    if (msg.final) {
      settle(null);
    }
  };

  const unsubscribe = sig.subscribe((msg) => {
    if (settled) return;
    if (msg.type === "session_error") {
      settle(new Error(`${msg.code}: ${msg.message}`));
      return;
    }
    if (msg.type !== "control_stream_chunk" || msg.stream !== stream) return;
    // Decompression is asynchronous; the chain keeps segments in arrival order
    chain = chain
      .then(() => handleSegment(msg))
      .catch((err) => settle(err instanceof Error ? err : new Error(String(err))));
  });

  return {
    done,
    expectComplete: () => {
      chain = chain.then(() =>
        settle(
          new Error(
            `CONTROL_STREAM_INTEGRITY: "${stream}" ended after ${expectedIndex} segments without its final segment`,
          ),
        ),
      );
    },
    cancel: () => settle(new Error(`Control stream "${stream}" was cancelled`)),
  };
}
