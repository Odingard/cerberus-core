/**
 * Unit tests — IntelligenceValidation Zod schemas (types.ts)
 *
 * Proves that every schema accepts valid data, rejects invalid data, and
 * that the full VerdictWeightResponseSchema round-trips correctly for each
 * of the three verdict actions (PASS / FLAG / BLOCK).
 *
 * These are mathematical correctness proofs for the schema layer: if a
 * bridge response passes VerdictWeightResponseSchema.safeParse(), Cerberus
 * will route it correctly. If it fails, the error message will identify the
 * offending field — no silent data corruption.
 */

import { describe, it, expect } from 'vitest';
import {
  VerdictActionSchema,
  ConsequenceWeightLabelSchema,
  CryptographicIntegrityStatus,
  RoutingDecisionSchema,
  CommercialTierSchema,
  AdversarialTierSchema,
  CryptographicTierSchema,
  StreamDiagnosticsSchema,
  ExecutionMetricsSchema,
  VerdictWeightResponseSchema,
  McpCallToolResultSchema,
  McpToolResultContentSchema,
} from '../../src/intelligence-validation/types.js';

// ── Shared fixture factory ──────────────────────────────────────────────────

function makeFullVwResponse(overrides: Record<string, unknown> = {}) {
  return {
    transaction_id: 'vw_tx_schema_test',
    timestamp: '2024-01-01T00:00:00Z',
    payload_hash: 'abcdef1234567890',
    routing_decision: {
      action: 'PASS',
      signal_strength: 0.85,
      doubt_index: 0.12,
      consequence_weight: 'LOW',
      reason_code: 'OK',
    },
    stream_diagnostics: {
      commercial_tier: {
        stream_1_source_reliability: 0.92,
        stream_2_cross_feed_corroboration: 0.6,
        stream_3_temporal_decay: 1.0,
        stream_4_historical_accuracy: 1.0,
      },
      adversarial_tier: {
        stream_5_cross_temporal_consistency: 0.95,
        trajectory_anomaly_detected: false,
        identified_vectors: [],
      },
      cryptographic_tier: {
        stream_6_hash_integrity: 'PASS',
        stream_7_origin_signature: 'PASS',
        stream_8_chain_of_custody: 'PASS',
      },
    },
    execution_metrics: { latency_ms: 8 },
    ...overrides,
  };
}

// ── VerdictActionSchema ────────────────────────────────────────────────────

describe('VerdictActionSchema', () => {
  it('should accept PASS', () => {
    expect(VerdictActionSchema.safeParse('PASS').success).toBe(true);
  });

  it('should accept FLAG', () => {
    expect(VerdictActionSchema.safeParse('FLAG').success).toBe(true);
  });

  it('should accept BLOCK', () => {
    expect(VerdictActionSchema.safeParse('BLOCK').success).toBe(true);
  });

  it('should reject lowercase "pass"', () => {
    expect(VerdictActionSchema.safeParse('pass').success).toBe(false);
  });

  it('should reject arbitrary string "ALLOW"', () => {
    expect(VerdictActionSchema.safeParse('ALLOW').success).toBe(false);
  });

  it('should reject empty string', () => {
    expect(VerdictActionSchema.safeParse('').success).toBe(false);
  });

  it('should reject null', () => {
    expect(VerdictActionSchema.safeParse(null).success).toBe(false);
  });
});

// ── ConsequenceWeightLabelSchema ────────────────────────────────────────────

describe('ConsequenceWeightLabelSchema', () => {
  it('should accept LOW', () => {
    expect(ConsequenceWeightLabelSchema.safeParse('LOW').success).toBe(true);
  });

  it('should accept MED', () => {
    expect(ConsequenceWeightLabelSchema.safeParse('MED').success).toBe(true);
  });

  it('should accept HIGH', () => {
    expect(ConsequenceWeightLabelSchema.safeParse('HIGH').success).toBe(true);
  });

  it('should reject "MEDIUM"', () => {
    expect(ConsequenceWeightLabelSchema.safeParse('MEDIUM').success).toBe(false);
  });

  it('should reject "CRITICAL"', () => {
    expect(ConsequenceWeightLabelSchema.safeParse('CRITICAL').success).toBe(false);
  });

  it('should reject lowercase "high"', () => {
    expect(ConsequenceWeightLabelSchema.safeParse('high').success).toBe(false);
  });
});

// ── CryptographicIntegrityStatus ────────────────────────────────────────────

describe('CryptographicIntegrityStatus', () => {
  const valid = ['PASS', 'FAIL', 'VALID', 'INVALID', 'INTACT', 'BROKEN'] as const;

  for (const status of valid) {
    it(`should accept "${status}"`, () => {
      expect(CryptographicIntegrityStatus.safeParse(status).success).toBe(true);
    });
  }

  it('should reject "UNKNOWN"', () => {
    expect(CryptographicIntegrityStatus.safeParse('UNKNOWN').success).toBe(false);
  });

  it('should reject lowercase "pass"', () => {
    expect(CryptographicIntegrityStatus.safeParse('pass').success).toBe(false);
  });
});

// ── RoutingDecisionSchema ──────────────────────────────────────────────────

describe('RoutingDecisionSchema', () => {
  const validDecision = {
    action: 'BLOCK',
    signal_strength: 0.01,
    doubt_index: 0.99,
    consequence_weight: 'HIGH',
    reason_code: 'ERR_ADV_TRAJECTORY_PATTERN_C',
  };

  it('should accept a valid routing decision', () => {
    expect(RoutingDecisionSchema.safeParse(validDecision).success).toBe(true);
  });

  it('should accept boundary doubt_index of 0.0', () => {
    expect(RoutingDecisionSchema.safeParse({ ...validDecision, doubt_index: 0.0 }).success).toBe(
      true,
    );
  });

  it('should accept boundary doubt_index of 1.0', () => {
    expect(RoutingDecisionSchema.safeParse({ ...validDecision, doubt_index: 1.0 }).success).toBe(
      true,
    );
  });

  it('should reject doubt_index > 1.0', () => {
    expect(RoutingDecisionSchema.safeParse({ ...validDecision, doubt_index: 1.001 }).success).toBe(
      false,
    );
  });

  it('should reject doubt_index < 0.0', () => {
    expect(RoutingDecisionSchema.safeParse({ ...validDecision, doubt_index: -0.01 }).success).toBe(
      false,
    );
  });

  it('should reject signal_strength > 1.0', () => {
    expect(
      RoutingDecisionSchema.safeParse({ ...validDecision, signal_strength: 1.1 }).success,
    ).toBe(false);
  });

  it('should reject missing reason_code', () => {
    const { reason_code: _rc, ...withoutRc } = validDecision;
    expect(RoutingDecisionSchema.safeParse(withoutRc).success).toBe(false);
  });

  it('should reject extra unknown field (strictObject)', () => {
    expect(
      RoutingDecisionSchema.safeParse({ ...validDecision, extra_field: 'surprise' }).success,
    ).toBe(false);
  });
});

// ── CommercialTierSchema ────────────────────────────────────────────────────

describe('CommercialTierSchema', () => {
  const validTier = {
    stream_1_source_reliability: 0.92,
    stream_2_cross_feed_corroboration: 0.6,
    stream_3_temporal_decay: 1.0,
    stream_4_historical_accuracy: 1.0,
  };

  it('should accept a valid commercial tier', () => {
    expect(CommercialTierSchema.safeParse(validTier).success).toBe(true);
  });

  it('should reject values out of range', () => {
    expect(
      CommercialTierSchema.safeParse({ ...validTier, stream_1_source_reliability: 1.5 }).success,
    ).toBe(false);
  });

  it('should reject missing stream_4_historical_accuracy', () => {
    const { stream_4_historical_accuracy: _s4, ...without } = validTier;
    expect(CommercialTierSchema.safeParse(without).success).toBe(false);
  });

  it('should reject extra fields (strictObject)', () => {
    expect(CommercialTierSchema.safeParse({ ...validTier, stream_9_extra: 0.5 }).success).toBe(
      false,
    );
  });
});

// ── AdversarialTierSchema ──────────────────────────────────────────────────

describe('AdversarialTierSchema', () => {
  const validTier = {
    stream_5_cross_temporal_consistency: 0.1,
    trajectory_anomaly_detected: true,
    identified_vectors: ['MCP_SMUGGLING_ATTEMPT', 'PATTERN_C_COLLAPSE'],
  };

  it('should accept a valid adversarial tier with attack vectors', () => {
    expect(AdversarialTierSchema.safeParse(validTier).success).toBe(true);
  });

  it('should accept an empty identified_vectors array', () => {
    expect(AdversarialTierSchema.safeParse({ ...validTier, identified_vectors: [] }).success).toBe(
      true,
    );
  });

  it('should accept CRYPTO_FORGERY in identified_vectors', () => {
    const result = AdversarialTierSchema.safeParse({
      ...validTier,
      identified_vectors: ['CRYPTO_FORGERY'],
    });
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.identified_vectors).toContain('CRYPTO_FORGERY');
    }
  });

  it('should reject non-boolean trajectory_anomaly_detected', () => {
    expect(
      AdversarialTierSchema.safeParse({
        ...validTier,
        trajectory_anomaly_detected: 'true',
      }).success,
    ).toBe(false);
  });

  it('should reject non-string items in identified_vectors', () => {
    expect(
      AdversarialTierSchema.safeParse({
        ...validTier,
        identified_vectors: [42, 'valid'],
      }).success,
    ).toBe(false);
  });
});

// ── CryptographicTierSchema ─────────────────────────────────────────────────

describe('CryptographicTierSchema', () => {
  it('should accept all-PASS tier (clean payload)', () => {
    expect(
      CryptographicTierSchema.safeParse({
        stream_6_hash_integrity: 'PASS',
        stream_7_origin_signature: 'PASS',
        stream_8_chain_of_custody: 'PASS',
      }).success,
    ).toBe(true);
  });

  it('should accept XBEN-095-CRYPTO-001 stream-7 forgery state', () => {
    // This is the exact state emitted by the Python bridge for CRYPTO-001
    expect(
      CryptographicTierSchema.safeParse({
        stream_6_hash_integrity: 'PASS',
        stream_7_origin_signature: 'BROKEN',
        stream_8_chain_of_custody: 'FAIL',
      }).success,
    ).toBe(true);
  });

  it('should reject invalid status value', () => {
    expect(
      CryptographicTierSchema.safeParse({
        stream_6_hash_integrity: 'PASS',
        stream_7_origin_signature: 'COMPROMISED', // not in enum
        stream_8_chain_of_custody: 'PASS',
      }).success,
    ).toBe(false);
  });
});

// ── StreamDiagnosticsSchema ─────────────────────────────────────────────────

describe('StreamDiagnosticsSchema', () => {
  const validDiagnostics = {
    commercial_tier: {
      stream_1_source_reliability: 0.92,
      stream_2_cross_feed_corroboration: 0.6,
      stream_3_temporal_decay: 1.0,
      stream_4_historical_accuracy: 1.0,
    },
    adversarial_tier: {
      stream_5_cross_temporal_consistency: 0.95,
      trajectory_anomaly_detected: false,
      identified_vectors: [],
    },
    cryptographic_tier: {
      stream_6_hash_integrity: 'PASS',
      stream_7_origin_signature: 'PASS',
      stream_8_chain_of_custody: 'PASS',
    },
  };

  it('should accept valid stream diagnostics', () => {
    expect(StreamDiagnosticsSchema.safeParse(validDiagnostics).success).toBe(true);
  });

  it('should reject missing adversarial_tier', () => {
    const { adversarial_tier: _at, ...without } = validDiagnostics;
    expect(StreamDiagnosticsSchema.safeParse(without).success).toBe(false);
  });

  it('should reject extra top-level field (strictObject)', () => {
    expect(
      StreamDiagnosticsSchema.safeParse({ ...validDiagnostics, behavioral_tier: {} }).success,
    ).toBe(false);
  });
});

// ── VerdictWeightResponseSchema — full round-trip proofs ──────────────────

describe('VerdictWeightResponseSchema — PASS round-trip', () => {
  it('should parse a clean PASS response', () => {
    const raw = makeFullVwResponse({
      routing_decision: {
        action: 'PASS',
        signal_strength: 0.88,
        doubt_index: 0.08,
        consequence_weight: 'LOW',
        reason_code: 'OK',
      },
    });
    const result = VerdictWeightResponseSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.routing_decision.action).toBe('PASS');
      expect(result.data.routing_decision.doubt_index).toBe(0.08);
      expect(result.data.routing_decision.consequence_weight).toBe('LOW');
    }
  });

  it('should preserve all required top-level fields on PASS', () => {
    const raw = makeFullVwResponse();
    const result = VerdictWeightResponseSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(typeof result.data.transaction_id).toBe('string');
      expect(typeof result.data.timestamp).toBe('string');
      expect(typeof result.data.payload_hash).toBe('string');
      expect(typeof result.data.execution_metrics.latency_ms).toBe('number');
    }
  });
});

describe('VerdictWeightResponseSchema — FLAG round-trip', () => {
  it('should parse a FLAG response', () => {
    const raw = makeFullVwResponse({
      routing_decision: {
        action: 'FLAG',
        signal_strength: 0.5,
        doubt_index: 0.55,
        consequence_weight: 'MED',
        reason_code: 'ERR_ADV_VECTOR_DETECTED',
      },
    });
    const result = VerdictWeightResponseSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.routing_decision.action).toBe('FLAG');
      expect(result.data.routing_decision.consequence_weight).toBe('MED');
    }
  });
});

describe('VerdictWeightResponseSchema — BLOCK round-trip', () => {
  it('should parse an MCP smuggling BLOCK response', () => {
    const raw = makeFullVwResponse({
      routing_decision: {
        action: 'BLOCK',
        signal_strength: 0.24,
        doubt_index: 0.92,
        consequence_weight: 'HIGH',
        reason_code: 'ERR_ADV_TRAJECTORY_PATTERN_C',
      },
      stream_diagnostics: {
        commercial_tier: {
          stream_1_source_reliability: 0.12,
          stream_2_cross_feed_corroboration: 0.2,
          stream_3_temporal_decay: 1.0,
          stream_4_historical_accuracy: 0.5,
        },
        adversarial_tier: {
          stream_5_cross_temporal_consistency: 0.1,
          trajectory_anomaly_detected: true,
          identified_vectors: ['MCP_SMUGGLING_ATTEMPT', 'PATTERN_C_COLLAPSE'],
        },
        cryptographic_tier: {
          stream_6_hash_integrity: 'FAIL',
          stream_7_origin_signature: 'INVALID',
          stream_8_chain_of_custody: 'BROKEN',
        },
      },
    });
    const result = VerdictWeightResponseSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.routing_decision.action).toBe('BLOCK');
      expect(result.data.routing_decision.doubt_index).toBe(0.92);
      expect(result.data.stream_diagnostics.adversarial_tier.identified_vectors).toContain(
        'MCP_SMUGGLING_ATTEMPT',
      );
      expect(result.data.stream_diagnostics.adversarial_tier.identified_vectors).toContain(
        'PATTERN_C_COLLAPSE',
      );
      expect(result.data.stream_diagnostics.cryptographic_tier.stream_7_origin_signature).toBe(
        'INVALID',
      );
    }
  });

  it('should parse XBEN-095-CRYPTO-001 stream-7 forgery BLOCK response', () => {
    // This validates the exact response shape emitted by the Python bridge
    // for the CRYPTO-001 vector: text scanner sees 0 hits but stream diagnostics
    // detect the forged origin signature.
    const raw = makeFullVwResponse({
      transaction_id: 'vw_tx_mock_crypto_01',
      payload_hash: 'cryptomockhash',
      routing_decision: {
        action: 'BLOCK',
        signal_strength: 0.01,
        doubt_index: 0.99,
        consequence_weight: 'HIGH',
        reason_code: 'ERR_CRYPTO_ORIGIN_SIGNATURE_BROKEN',
      },
      stream_diagnostics: {
        commercial_tier: {
          stream_1_source_reliability: 0.12,
          stream_2_cross_feed_corroboration: 0.2,
          stream_3_temporal_decay: 1.0,
          stream_4_historical_accuracy: 0.5,
        },
        adversarial_tier: {
          stream_5_cross_temporal_consistency: 0.95,
          trajectory_anomaly_detected: false,
          identified_vectors: ['CRYPTO_FORGERY'],
        },
        cryptographic_tier: {
          stream_6_hash_integrity: 'PASS',
          stream_7_origin_signature: 'BROKEN',
          stream_8_chain_of_custody: 'FAIL',
        },
      },
      execution_metrics: { latency_ms: 9 },
    });
    const result = VerdictWeightResponseSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      // Stream 7 is the only failure — text scanner sees 0 hits
      expect(result.data.stream_diagnostics.cryptographic_tier.stream_6_hash_integrity).toBe(
        'PASS',
      );
      expect(result.data.stream_diagnostics.cryptographic_tier.stream_7_origin_signature).toBe(
        'BROKEN',
      );
      expect(result.data.stream_diagnostics.adversarial_tier.identified_vectors).toContain(
        'CRYPTO_FORGERY',
      );
      expect(result.data.stream_diagnostics.adversarial_tier.trajectory_anomaly_detected).toBe(
        false,
      );
      expect(result.data.routing_decision.reason_code).toBe('ERR_CRYPTO_ORIGIN_SIGNATURE_BROKEN');
      expect(result.data.routing_decision.doubt_index).toBe(0.99);
    }
  });
});

describe('VerdictWeightResponseSchema — rejection cases', () => {
  it('should reject missing transaction_id', () => {
    const raw = makeFullVwResponse();
    const { transaction_id: _tid, ...without } = raw;
    expect(VerdictWeightResponseSchema.safeParse(without).success).toBe(false);
  });

  it('should reject missing stream_diagnostics', () => {
    const raw = makeFullVwResponse();
    const { stream_diagnostics: _sd, ...without } = raw;
    expect(VerdictWeightResponseSchema.safeParse(without).success).toBe(false);
  });

  it('should reject extra top-level fields (strictObject)', () => {
    const raw = { ...makeFullVwResponse(), _simulated_metadata: { foo: 'bar' } };
    expect(VerdictWeightResponseSchema.safeParse(raw).success).toBe(false);
  });

  it('should reject a response with invalid action', () => {
    const raw = makeFullVwResponse({
      routing_decision: {
        action: 'QUARANTINE', // not in enum
        signal_strength: 0.5,
        doubt_index: 0.5,
        consequence_weight: 'HIGH',
        reason_code: 'TEST',
      },
    });
    expect(VerdictWeightResponseSchema.safeParse(raw).success).toBe(false);
  });

  it('should provide a descriptive error for missing required field', () => {
    const raw = makeFullVwResponse();
    const { execution_metrics: _em, ...without } = raw;
    const result = VerdictWeightResponseSchema.safeParse(without);
    expect(result.success).toBe(false);
    if (!result.success) {
      // Error message should identify the missing field
      expect(result.error.message).toBeTruthy();
    }
  });
});

// ── McpCallToolResultSchema ────────────────────────────────────────────────

describe('McpCallToolResultSchema — passthrough boundary', () => {
  it('should accept a standard MCP tool result', () => {
    const result = McpCallToolResultSchema.safeParse({
      content: [{ type: 'text', text: 'Hello world' }],
    });
    expect(result.success).toBe(true);
  });

  it('should preserve _simulated_metadata via passthrough (CRYPTO-001)', () => {
    const raw = {
      content: [
        {
          type: 'text',
          text: 'Q3 earnings summary: Revenue increased by 4.2% year-over-year.',
        },
      ],
      _simulated_metadata: { vw_trigger_failure: 'STREAM_7_ORIGIN_FORGED' },
    };
    const result = McpCallToolResultSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      // passthrough() preserves the field
      expect('_simulated_metadata' in result.data).toBe(true);
      const meta = result.data['_simulated_metadata'] as Record<string, unknown>;
      expect(meta['vw_trigger_failure']).toBe('STREAM_7_ORIGIN_FORGED');
    }
  });

  it('should accept an isError result', () => {
    expect(
      McpCallToolResultSchema.safeParse({
        content: [{ type: 'text', text: 'Something went wrong' }],
        isError: true,
      }).success,
    ).toBe(true);
  });

  it('should accept an empty content array', () => {
    expect(McpCallToolResultSchema.safeParse({ content: [] }).success).toBe(true);
  });

  it('should accept a result with no content field (optional)', () => {
    expect(McpCallToolResultSchema.safeParse({}).success).toBe(true);
  });
});

describe('McpToolResultContentSchema — passthrough boundary', () => {
  it('should accept standard type+text content', () => {
    expect(McpToolResultContentSchema.safeParse({ type: 'text', text: 'hello' }).success).toBe(
      true,
    );
  });

  it('should preserve extra fields via passthrough (vendor extensions)', () => {
    const raw = { type: 'image', url: 'https://example.com/img.png', mimeType: 'image/png' };
    const result = McpToolResultContentSchema.safeParse(raw);
    expect(result.success).toBe(true);
    if (result.success) {
      expect('url' in result.data).toBe(true);
    }
  });

  it('should accept a content item with no fields (fully optional)', () => {
    expect(McpToolResultContentSchema.safeParse({}).success).toBe(true);
  });
});

// ── ExecutionMetricsSchema ─────────────────────────────────────────────────

describe('ExecutionMetricsSchema', () => {
  it('should accept latency_ms = 0', () => {
    expect(ExecutionMetricsSchema.safeParse({ latency_ms: 0 }).success).toBe(true);
  });

  it('should accept large latency values', () => {
    expect(ExecutionMetricsSchema.safeParse({ latency_ms: 99999 }).success).toBe(true);
  });

  it('should reject negative latency_ms', () => {
    expect(ExecutionMetricsSchema.safeParse({ latency_ms: -1 }).success).toBe(false);
  });

  it('should reject missing latency_ms', () => {
    expect(ExecutionMetricsSchema.safeParse({}).success).toBe(false);
  });

  it('should reject extra fields (strictObject)', () => {
    expect(ExecutionMetricsSchema.safeParse({ latency_ms: 5, cpu_ms: 3 }).success).toBe(false);
  });
});
