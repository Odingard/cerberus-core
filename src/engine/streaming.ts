import type { CerberusConfig } from '../types/config.js';

function isReadableStream(value: unknown): value is ReadableStream<Uint8Array | string> {
  return typeof value === 'object' && value !== null && 'getReader' in value;
}

function isAsyncIterable(value: unknown): value is AsyncIterable<unknown> {
  return typeof value === 'object' && value !== null && Symbol.asyncIterator in value;
}

function isIterable(value: unknown): value is Iterable<unknown> {
  return typeof value === 'object' && value !== null && Symbol.iterator in value;
}

function chunkToString(chunk: unknown): string {
  if (typeof chunk === 'string') return chunk;
  if (chunk instanceof Uint8Array) return new TextDecoder().decode(chunk);
  if (typeof chunk === 'number' || typeof chunk === 'boolean' || typeof chunk === 'bigint') {
    return String(chunk);
  }
  if (chunk === undefined || chunk === null) return '';
  try {
    return JSON.stringify(chunk);
  } catch {
    return '[unserializable-stream-chunk]';
  }
}

function valueToString(value: unknown): string {
  if (typeof value === 'string') return value;
  if (value instanceof Uint8Array) return new TextDecoder().decode(value);
  if (typeof value === 'number' || typeof value === 'boolean' || typeof value === 'bigint') {
    return String(value);
  }
  if (value === undefined || value === null) return '';
  try {
    return JSON.stringify(value);
  } catch {
    return '[unserializable-tool-result]';
  }
}

/**
 * Reconstruct a full tool result string before the detection pipeline runs.
 *
 * This ensures streamed tool output is inspected at a turn boundary rather
 * than chunk-by-chunk, which avoids acting on partial content before Cerberus
 * has seen the whole payload.
 */
export async function collectToolResult(result: unknown, config: CerberusConfig): Promise<string> {
  if (typeof result === 'string') {
    return result;
  }

  const streamingMode = config.streamingMode ?? 'buffer';

  const isStreamLike = isReadableStream(result) || isAsyncIterable(result) || isIterable(result);
  if (!isStreamLike) {
    return valueToString(result);
  }

  if (streamingMode === 'reject') {
    throw new Error(
      '[Cerberus Streaming] Stream-like tool results require "streamingMode: buffer" so Cerberus can reconstruct a full turn before inspection.',
    );
  }

  if (isReadableStream(result)) {
    const reader = result.getReader();
    const chunks: string[] = [];
    let finished = false;
    while (!finished) {
      const { done: readerDone, value } = await reader.read();
      if (readerDone) {
        finished = true;
      } else {
        chunks.push(chunkToString(value));
      }
    }
    return chunks.join('');
  }

  if (isAsyncIterable(result)) {
    const chunks: string[] = [];
    for await (const chunk of result) {
      chunks.push(chunkToString(chunk));
    }
    return chunks.join('');
  }

  const chunks: string[] = [];
  for (const chunk of result) {
    chunks.push(chunkToString(chunk));
  }
  return chunks.join('');
}
