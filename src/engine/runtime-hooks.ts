/**
 * Runtime hooks — the dependency-inversion seam between the open detection
 * engine and the licensed deployment stack.
 *
 * The open interceptor calls two paid surfaces mid-pipeline: OpenTelemetry
 * recording (`config.opentelemetry`) and the enforcement-gateway dispatch
 * (`config.enforcement`). Those implementations are licensed and live in
 * `@cerberus-ai/enterprise`; the open tier must not import them.
 *
 * Instead the open engine emits through these registered hooks. The default is a
 * no-op: importing `@cerberus-ai/enterprise` registers the real implementations.
 * If a deployer SETS `config.opentelemetry` / `config.enforcement` but no
 * implementation is registered (the paid package is not installed), the hook
 * warns ONCE rather than silently doing nothing — the same honest-coverage
 * principle the engine applies everywhere: never quietly misrepresent what is
 * (and isn't) running.
 */

import type { RiskAssessment } from '../types/signals.js';
import type { ToolExecutionOutcome } from '../types/execution.js';
import type { EnforcementConfig } from '../enforcement/types.js';

// ── OpenTelemetry recording hook ────────────────────────────────────

/** One tool-call observation handed to the telemetry recorder. */
export interface TelemetryToolCallRecord {
  readonly toolName: string;
  readonly sessionId: string;
  readonly turnId: string;
  readonly score: number;
  readonly action: string;
  readonly blocked: boolean;
  readonly signals: readonly string[];
  readonly durationMs: number;
}

/** A telemetry recorder injected by `@cerberus-ai/enterprise`. */
export type TelemetryRecorder = (record: TelemetryToolCallRecord) => void;

let telemetryRecorder: TelemetryRecorder | null = null;
let warnedTelemetryMissing = false;

/** Register the licensed telemetry recorder (called by `@cerberus-ai/enterprise`). */
export function setTelemetryRecorder(recorder: TelemetryRecorder): void {
  telemetryRecorder = recorder;
}

/** Remove the registered telemetry recorder (test teardown / open default). */
export function resetTelemetryRecorder(): void {
  telemetryRecorder = null;
  warnedTelemetryMissing = false;
}

/** Whether a licensed telemetry recorder is registered. */
export function hasTelemetryRecorder(): boolean {
  return telemetryRecorder !== null;
}

/**
 * Emit a tool-call observation to the registered recorder. Called by the
 * interceptor only when `config.opentelemetry === true`; warns once if no
 * recorder is registered (paid package not installed) so the gap is loud.
 */
export function emitTelemetry(record: TelemetryToolCallRecord): void {
  if (telemetryRecorder) {
    telemetryRecorder(record);
    return;
  }
  if (!warnedTelemetryMissing) {
    warnedTelemetryMissing = true;
    // eslint-disable-next-line no-console
    console.warn(
      '[Cerberus] config.opentelemetry is set but no telemetry recorder is registered. ' +
        'OpenTelemetry instrumentation is a licensed feature — install and import ' +
        '@cerberus-ai/enterprise to enable it. Recording is a no-op until then.',
    );
  }
}

// ── Enforcement-gateway dispatch hook ───────────────────────────────

/** Inputs for an enforcement-gateway dispatch on a blocked tool call. */
export interface EnforcementDispatchInput {
  readonly sessionId: string;
  readonly assessment: RiskAssessment;
  readonly outcome: ToolExecutionOutcome;
  readonly enforcement: EnforcementConfig;
}

/** An enforcement dispatcher injected by `@cerberus-ai/enterprise`. */
export type EnforcementDispatch = (input: EnforcementDispatchInput) => void;

let enforcementDispatch: EnforcementDispatch | null = null;
let warnedEnforcementMissing = false;

/** Register the licensed enforcement dispatcher (called by `@cerberus-ai/enterprise`). */
export function setEnforcementDispatch(dispatch: EnforcementDispatch): void {
  enforcementDispatch = dispatch;
}

/** Remove the registered enforcement dispatcher (test teardown / open default). */
export function resetEnforcementDispatch(): void {
  enforcementDispatch = null;
  warnedEnforcementMissing = false;
}

/** Whether a licensed enforcement dispatcher is registered. */
export function hasEnforcementDispatch(): boolean {
  return enforcementDispatch !== null;
}

/**
 * Emit an enforcement-gateway dispatch for a blocked tool call. Called by the
 * interceptor only when `config.enforcement` is set; warns once if no dispatcher
 * is registered (paid package not installed) so the gap is loud.
 */
export function emitEnforcement(input: EnforcementDispatchInput): void {
  if (enforcementDispatch) {
    enforcementDispatch(input);
    return;
  }
  if (!warnedEnforcementMissing) {
    warnedEnforcementMissing = true;
    // eslint-disable-next-line no-console
    console.warn(
      '[Cerberus] config.enforcement is set but no enforcement dispatcher is registered. ' +
        'The enforcement gateway is a licensed feature — install and import ' +
        '@cerberus-ai/enterprise to enable it. Dispatch is a no-op until then.',
    );
  }
}
