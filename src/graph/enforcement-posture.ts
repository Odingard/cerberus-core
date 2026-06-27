/**
 * Enforcement-posture derivation (Assurance Axis 3a).
 *
 * Derives the effective per-layer enforcement posture from the in-force
 * {@link CerberusConfig}, so it can be bound into the signed delegation
 * manifest (the receipt attests *what enforcement authority was in force*, not
 * just what was protected). This is a pure function of config — the receipt
 * binds a genuinely-derived posture, never a fabricated one.
 *
 * Depends on: src/types/config.ts, src/graph/delegation.ts
 */

import type { AlertMode, CerberusConfig } from '../types/config.js';
import type { EnforcementLayer, EnforcementMode, EnforcementPosture } from './delegation.js';

/**
 * Map the deployment's {@link AlertMode} to the per-layer {@link EnforcementMode}.
 * `log` observes/records without interrupting; `alert` flags without
 * interrupting; `interrupt` blocks.
 */
const ALERT_MODE_TO_ENFORCEMENT: Readonly<Record<AlertMode, EnforcementMode>> = {
  log: 'record-only',
  alert: 'flag',
  interrupt: 'block',
};

/**
 * Derive the effective per-layer enforcement posture from the in-force config.
 *
 * - Detection layers **L1/L2/L3** follow `alertMode` (default `'alert'`).
 * - **L4** (memory-contamination tracking) is only in force when
 *   `memoryTracking` is enabled; when disabled it is **omitted** from the
 *   posture — a layer that is not running is not bound as if it were (honest
 *   binding, and the source of the 3a binding-completeness residual).
 * - **INTEGRITY** (the signed-manifest / crypto gate) is **always** fail-closed
 *   (`'block'`) regardless of `alertMode` — it cannot be downgraded to
 *   observe-only, so it is always bound at `'block'`.
 */
export function deriveEnforcementPosture(config: CerberusConfig): EnforcementPosture {
  const mode = ALERT_MODE_TO_ENFORCEMENT[config.alertMode ?? 'alert'];
  const posture: { -readonly [K in EnforcementLayer]?: EnforcementMode } = {
    L1: mode,
    L2: mode,
    L3: mode,
    INTEGRITY: 'block',
  };
  if (config.memoryTracking) {
    posture.L4 = mode;
  }
  return posture;
}
