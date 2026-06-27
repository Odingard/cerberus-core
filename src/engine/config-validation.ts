import type { MemoryToolConfig } from '../layers/l4-memory.js';
import type { CerberusConfig, TrustOverride } from '../types/config.js';
import type { Signer, SignerVerifier } from '../crypto/signer.js';

interface ValidateConfigOptions {
  readonly outboundTools?: readonly string[];
  readonly memoryTools?: readonly MemoryToolConfig[];
}

/** Whether a configured manifest signer can also verify its own signatures. */
function signerCanVerify(signer: Signer | SignerVerifier): boolean {
  return 'verify' in signer && typeof signer.verify === 'function';
}

function ensureUniqueTrustOverrides(trustOverrides: readonly TrustOverride[]): void {
  const seen = new Set<string>();
  for (const override of trustOverrides) {
    if (seen.has(override.toolName)) {
      throw new Error(
        `[Cerberus Config] Duplicate trust override for tool "${override.toolName}". Each tool may only be classified once.`,
      );
    }
    seen.add(override.toolName);
  }
}

/**
 * Validate Cerberus startup configuration and fail fast on states that would
 * silently weaken protection in production.
 */
export function validateCerberusConfig(
  config: CerberusConfig,
  options: ValidateConfigOptions = {},
): void {
  if (
    config.threshold !== undefined &&
    (!Number.isInteger(config.threshold) || config.threshold < 0 || config.threshold > 4)
  ) {
    throw new Error('[Cerberus Config] "threshold" must be an integer between 0 and 4.');
  }

  if (config.provenanceSummary !== undefined) {
    const s = config.provenanceSummary;
    if (s.kind !== undefined && s.kind !== 'bloom' && s.kind !== 'accumulator') {
      throw new Error(
        '[Cerberus Config] "provenanceSummary.kind" must be "bloom" or "accumulator".',
      );
    }
    if (!Number.isFinite(s.bitsPerNode) || s.bitsPerNode <= 0) {
      throw new Error(
        '[Cerberus Config] "provenanceSummary.bitsPerNode" must be a positive number.',
      );
    }
    if (s.hashes !== undefined && (!Number.isFinite(s.hashes) || s.hashes < 1)) {
      throw new Error('[Cerberus Config] "provenanceSummary.hashes" must be >= 1 when provided.');
    }
  }

  if (
    config.multiAgent === true &&
    config.manifestSigner !== undefined &&
    !signerCanVerify(config.manifestSigner) &&
    config.manifestVerifier === undefined
  ) {
    throw new Error(
      '[Cerberus Config] "manifestSigner" is sign-only (no verify()) but no "manifestVerifier" was provided. Supply the public-key verifier so the per-turn manifest gate can verify; otherwise every turn would fail closed with VERIFIER_MISSING.',
    );
  }

  const trustOverrides = config.trustOverrides ?? [];
  ensureUniqueTrustOverrides(trustOverrides);

  const memoryTools = options.memoryTools ?? [];
  if (config.memoryTracking === true && memoryTools.length === 0) {
    throw new Error(
      '[Cerberus Config] "memoryTracking" is enabled but no memory tools were provided. Configure memoryOptions.memoryTools or disable memoryTracking.',
    );
  }

  const outboundTools = options.outboundTools ?? [];
  if (config.alertMode === 'interrupt' && outboundTools.length > 0) {
    const hasTrusted = trustOverrides.some((override) => override.trustLevel === 'trusted');
    const hasUntrusted = trustOverrides.some((override) => override.trustLevel === 'untrusted');

    if (!hasTrusted || !hasUntrusted) {
      throw new Error(
        '[Cerberus Config] "alertMode: interrupt" with outbound tools requires at least one trusted and one untrusted tool classification in trustOverrides. Without both, L1/L2 coverage is materially reduced.',
      );
    }
  }
}
