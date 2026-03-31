import type { MemoryToolConfig } from '../layers/l4-memory.js';
import type { CerberusConfig, TrustOverride } from '../types/config.js';

interface ValidateConfigOptions {
  readonly outboundTools?: readonly string[];
  readonly memoryTools?: readonly MemoryToolConfig[];
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
