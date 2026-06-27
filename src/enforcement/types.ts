/**
 * Enforcement Gateway — Types for deterministic enforcement signal emission.
 *
 * When Cerberus interrupts a tool call, it optionally emits a structured
 * {@link EnforcementSignal} to one or more {@link EnforcementGateway}
 * backends. Downstream network gates (firewalls, eBPF, reverse proxies)
 * can ingest these signals to enforce at their own layer.
 *
 * Cerberus's primary enforcement is preventive (preflight block — the
 * outbound payload never reaches the network stack). The enforcement
 * signal provides defense-in-depth: even if the in-process block is
 * bypassed, the downstream gate has what it needs to act.
 */

import type { RiskVector, RiskAction } from '../types/signals.js';
import type { ToolExecutionPhase } from '../types/execution.js';

/** Graduated enforcement actions beyond binary block/allow. */
export type EnforcementAction = 'block' | 'throttle' | 'quarantine' | 'redirect' | 'alert';

/**
 * Deterministic enforcement signal emitted on every interrupt decision.
 *
 * Carries enough context for a downstream gate to:
 *   1. Identify the connection/session to act on
 *   2. Understand the risk that triggered the enforcement
 *   3. Verify the signal's authenticity (optional signature)
 */
export interface EnforcementSignal {
  /** Unique signal identifier (UUID v4). */
  readonly signalId: string;
  /** Stable incident identifier (session:turn composite). */
  readonly incidentId: string;
  /** Session where the enforcement occurred. */
  readonly sessionId: string;
  /** Turn that triggered the enforcement. */
  readonly turnId: string;
  /** Epoch milliseconds when the signal was generated. */
  readonly timestamp: number;

  /** Enforcement action for the downstream gate. */
  readonly action: EnforcementAction;
  /** Tool that was intercepted. */
  readonly toolName: string;
  /** Where in the pipeline the decision was made. */
  readonly phase: ToolExecutionPhase;

  /** Correlated risk score (0–4). */
  readonly riskScore: number;
  /** Four-layer risk vector. */
  readonly riskVector: RiskVector;
  /** Cerberus action that triggered this signal. */
  readonly triggerAction: RiskAction;
  /** Signal names that contributed to the enforcement decision. */
  readonly triggerSignals: readonly string[];

  /** Outbound destination when present (for network-layer enforcement). */
  readonly outboundDestination?: string;
  /** Fields matched for exfiltration (context for audit). */
  readonly exfiltrationFields?: readonly string[];

  /** True when Cerberus blocked before the executor ran (payload never hit the wire). */
  readonly preflightBlocked: boolean;
  /** Whether the underlying tool executor ran before the block. */
  readonly executorRan: boolean;

  /** Ed25519 signature over the canonical signal payload. */
  readonly signature?: string;
  /** Key identifier for signature verification. */
  readonly keyId?: string;
}

/**
 * Pluggable enforcement backend.
 *
 * Implementations deliver the signal to downstream infrastructure:
 * webhook endpoints, gRPC services, eBPF map updates, in-process
 * callbacks, message queues, etc.
 */
export interface EnforcementGateway {
  /** Human-readable name for logging and diagnostics. */
  readonly name: string;

  /**
   * Deliver an enforcement signal.
   *
   * Implementations SHOULD be non-blocking and fail-open: if delivery
   * fails, the Cerberus in-process block is still in effect.
   */
  dispatch(signal: EnforcementSignal): Promise<void> | void;

  /** Tear down resources (close connections, flush buffers). */
  close?(): Promise<void> | void;
}

/** Signing function for enforcement signal payloads. */
export type EnforcementSigner = (canonicalPayload: string) => {
  readonly signature: string;
  readonly keyId: string;
};

/**
 * Configuration for the enforcement egress layer.
 *
 * Added to {@link CerberusConfig} as `enforcement`.
 */
export interface EnforcementConfig {
  /** One or more gateways to dispatch enforcement signals to. */
  readonly gateways: EnforcementGateway | readonly EnforcementGateway[];

  /**
   * Enforcement action to embed in the signal.
   * Default: 'block'.
   */
  readonly action?: EnforcementAction;

  /**
   * Optional signer for cryptographic binding.
   * When provided, every enforcement signal is signed before dispatch.
   */
  readonly signer?: EnforcementSigner;
}
