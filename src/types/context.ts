/**
 * Runtime context passed to detection layers for each tool call.
 * This is the generic interface — not tied to any specific agent framework.
 */

import type { TurnId, SessionId } from './signals.js';

/** Describes a single tool invocation for detection analysis. */
export interface ToolCallContext {
  readonly turnId: TurnId;
  readonly sessionId: SessionId;
  readonly toolName: string;
  readonly toolArguments: Record<string, unknown>;
  readonly toolResult: string;
  readonly timestamp: number;
}
