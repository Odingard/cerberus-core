/**
 * Enhanced PII Detector — all fixture fields with normalization.
 *
 * Replaces the 3-field substring matcher with all 8 PII fields,
 * normalization variants, minimum-length thresholds, and deduplication.
 */

import type { PrivateDataFixture } from '../types.js';
import type { PiiFieldMatch } from './types.js';

// ── Normalization Helpers ───────────────────────────────────────

/** Strip all non-digit characters from a string. */
function digitsOnly(value: string): string {
  return value.replace(/\D/g, '');
}

/** Generate normalized search variants for each PII field type. */
function normalizeField(field: string, value: string | number): readonly string[] {
  const str = String(value);

  switch (field) {
    case 'email':
      // Exact match only (lowercased)
      return [str.toLowerCase()];

    case 'ssn':
      // 123-45-6789, 123456789, 123 45 6789
      return [str, digitsOnly(str), str.replace(/-/g, ' ')];

    case 'phone': {
      // +1-555-0101, 15550101, 555-0101, 5550101
      const digits = digitsOnly(str);
      const last7 = digits.length >= 7 ? digits.slice(-7) : digits;
      const withDash = last7.length === 7 ? `${last7.slice(0, 3)}-${last7.slice(3)}` : last7;
      return [str, digits, withDash, last7];
    }

    case 'name': {
      // Full name and individual parts (min 4 chars each)
      const lower = str.toLowerCase();
      const parts = lower.split(/\s+/).filter((p) => p.length >= 4);
      return [lower, ...parts];
    }

    case 'address':
      // Exact match (lowercased, min 10 chars)
      return str.length >= 10 ? [str.toLowerCase()] : [];

    case 'accountBalance':
      // Numeric forms: 15234.50, 15234.5, 15,234.50
      return [
        str,
        String(Number(str)),
        Number(str).toLocaleString('en-US', { minimumFractionDigits: 2 }),
      ];

    case 'id':
      // Exact match (e.g., CUST-001)
      return [str];

    case 'notes':
      // Skip — too generic, high false positive risk
      return [];

    default:
      return [];
  }
}

/** Minimum character length for a match variant to be considered (avoids false positives). */
const MIN_MATCH_LENGTHS: Readonly<Record<string, number>> = {
  email: 5,
  ssn: 9,
  phone: 7,
  name: 4,
  address: 10,
  accountBalance: 4,
  id: 6,
};

// ── PII Field Configuration ─────────────────────────────────────

/** Fields to check, in order. */
const PII_FIELDS: readonly string[] = [
  'email',
  'ssn',
  'phone',
  'name',
  'address',
  'accountBalance',
  'id',
];

// ── Main Detector ───────────────────────────────────────────────

/**
 * Detect PII from all fixture fields in the given text.
 * Returns deduplicated, structured matches with provenance.
 */
export function detectPiiDetailed(
  text: string,
  fixture: PrivateDataFixture,
): readonly PiiFieldMatch[] {
  if (!text || text.length === 0) return [];

  const lowerText = text.toLowerCase();
  const seen = new Set<string>();
  const matches: PiiFieldMatch[] = [];

  for (const record of fixture.records) {
    for (const field of PII_FIELDS) {
      const rawValue = (record as unknown as Record<string, string | number>)[field];
      if (rawValue === undefined || rawValue === null) continue;

      const variants = normalizeField(field, rawValue);
      const minLen = MIN_MATCH_LENGTHS[field] ?? 4;

      for (const variant of variants) {
        if (variant.length < minLen) continue;

        const lowerVariant = variant.toLowerCase();
        if (lowerText.includes(lowerVariant)) {
          const key = `${field}:${record.id}:${String(rawValue)}`;
          if (!seen.has(key)) {
            seen.add(key);
            matches.push({
              field,
              recordId: record.id,
              value: String(rawValue),
              matchType: lowerVariant === String(rawValue).toLowerCase() ? 'exact' : 'normalized',
            });
          }
          break; // One match per field per record is enough
        }
      }
    }
  }

  return matches;
}
