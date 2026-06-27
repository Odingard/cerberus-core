/**
 * Encoding/Obfuscation Detector — Sub-classifier enhancing L2.
 *
 * Detects when untrusted content contains encoded or obfuscated payloads,
 * a known bypass technique for injection scanners.
 */

import type { EncodingDetectedSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';

/** Encoding detection method with type label. */
interface EncodingMethod {
  readonly type: string;
  readonly pattern: RegExp;
  readonly decode?: (match: string) => string | null;
}

/** Try to decode a base64 string. Returns null if invalid. */
function tryDecodeBase64(text: string): string | null {
  try {
    const decoded = Buffer.from(text, 'base64').toString('utf-8');
    // Verify it's mostly printable characters
    const printable = decoded.replace(/[^\x20-\x7E\n\r\t]/g, '');
    if (printable.length / decoded.length > 0.7) {
      return decoded;
    }
    return null;
  } catch {
    return null;
  }
}

/** Try to decode hex escape sequences. */
function tryDecodeHex(text: string): string | null {
  try {
    const decoded = text.replace(/\\x([0-9a-fA-F]{2})/g, (_, hex: string) =>
      String.fromCharCode(parseInt(hex, 16)),
    );
    return decoded;
  } catch {
    return null;
  }
}

/** Try to decode unicode escape sequences. */
function tryDecodeUnicode(text: string): string | null {
  try {
    const decoded = text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex: string) =>
      String.fromCharCode(parseInt(hex, 16)),
    );
    return decoded;
  } catch {
    return null;
  }
}

/** Try to decode URL-encoded sequences. */
function tryDecodeUrl(text: string): string | null {
  try {
    return decodeURIComponent(text);
  } catch {
    return null;
  }
}

/** Encoding detection methods. */
const ENCODING_METHODS: readonly EncodingMethod[] = [
  {
    type: 'base64',
    pattern: /[A-Za-z0-9+/]{20,}={0,2}/g,
    decode: tryDecodeBase64,
  },
  {
    type: 'hex_escape',
    pattern: /(?:\\x[0-9a-fA-F]{2}){4,}/g,
    decode: tryDecodeHex,
  },
  {
    type: 'unicode_escape',
    pattern: /(?:\\u[0-9a-fA-F]{4}){3,}/g,
    decode: tryDecodeUnicode,
  },
  {
    type: 'url_encoding',
    pattern: /(?:%[0-9A-Fa-f]{2}){4,}/g,
    decode: tryDecodeUrl,
  },
  {
    type: 'html_entities',
    pattern: /(?:&#(?:\d+|x[0-9a-fA-F]+);){3,}/g,
  },
  {
    type: 'rot13_marker',
    pattern: /\brot13\b/gi,
  },
];

/**
 * Scan text for encoded/obfuscated content.
 * Returns detected encoding types and an optional decoded snippet.
 */
export function detectEncoding(text: string): {
  encodingTypes: string[];
  decodedContent?: string;
  decodedSnippet?: string;
} {
  const detectedTypes = new Set<string>();
  let firstDecodedContent: string | undefined;
  let firstDecodedSnippet: string | undefined;

  for (const method of ENCODING_METHODS) {
    method.pattern.lastIndex = 0;
    let match = method.pattern.exec(text);
    while (match) {
      detectedTypes.add(method.type);
      if (!firstDecodedSnippet && method.decode) {
        const decoded = method.decode(match[0]);
        if (decoded && decoded !== match[0]) {
          firstDecodedContent = decoded;
          firstDecodedSnippet = decoded.slice(0, 100);
        }
      }
      match = method.pattern.exec(text);
    }
  }

  return {
    encodingTypes: [...detectedTypes],
    ...(firstDecodedContent ? { decodedContent: firstDecodedContent } : {}),
    ...(firstDecodedSnippet ? { decodedSnippet: firstDecodedSnippet } : {}),
  };
}

/**
 * Detect encoding/obfuscation in a tool result and emit an L2 signal.
 * Only runs when the tool is untrusted (same gate as L2).
 */
export function detectEncodingInResult(
  ctx: ToolCallContext,
  _session: DetectionSession,
  isUntrusted: boolean,
): EncodingDetectedSignal | null {
  if (!isUntrusted) {
    return null;
  }

  const { encodingTypes, decodedSnippet } = detectEncoding(ctx.toolResult);
  if (encodingTypes.length === 0) {
    return null;
  }

  return {
    layer: 'L2',
    signal: 'ENCODING_DETECTED',
    turnId: ctx.turnId,
    encodingTypes,
    ...(decodedSnippet ? { decodedSnippet } : {}),
    timestamp: ctx.timestamp,
  };
}
