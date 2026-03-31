import { describe, it, expect } from 'vitest';
import { PAYLOADS } from '../../../harness/payloads.js';
import {
  PAYLOAD_DESTINATIONS,
  isSafeDomain,
  SAFE_DOMAINS,
} from '../../../harness/validation/payload-destinations.js';

describe('PAYLOAD_DESTINATIONS', () => {
  it('has an entry for every payload in PAYLOADS', () => {
    for (const payload of PAYLOADS) {
      expect(PAYLOAD_DESTINATIONS).toHaveProperty(payload.id);
    }
  });

  it('has no orphaned entries (every key maps to a real payload)', () => {
    const payloadIds = new Set(PAYLOADS.map((p) => p.id));
    for (const key of Object.keys(PAYLOAD_DESTINATIONS)) {
      expect(payloadIds.has(key)).toBe(true);
    }
  });

  it('AT-007 (benign control) has null destination', () => {
    expect(PAYLOAD_DESTINATIONS['AT-007']).toBeNull();
  });

  it('all non-null destinations are valid email addresses', () => {
    const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    for (const [id, dest] of Object.entries(PAYLOAD_DESTINATIONS)) {
      if (dest !== null) {
        expect(emailRe.test(dest), `${id}: "${dest}" is not a valid email`).toBe(true);
      }
    }
  });

  it('no attacker destination uses a safe domain', () => {
    for (const [id, dest] of Object.entries(PAYLOAD_DESTINATIONS)) {
      if (dest !== null) {
        expect(isSafeDomain(dest), `${id}: "${dest}" should not be a safe domain`).toBe(false);
      }
    }
  });
});

describe('isSafeDomain', () => {
  it('returns true for @acme.com', () => {
    expect(isSafeDomain('user@acme.com')).toBe(true);
  });

  it('returns true for @example.com', () => {
    expect(isSafeDomain('alice@example.com')).toBe(true);
  });

  it('returns true for subdomains of safe domains', () => {
    expect(isSafeDomain('user@reports.acme.com')).toBe(true);
  });

  it('returns false for external domains', () => {
    expect(isSafeDomain('attacker@evil.com')).toBe(false);
    expect(isSafeDomain('data@exfil.net')).toBe(false);
  });

  it('returns false for domains that contain safe domain as substring', () => {
    expect(isSafeDomain('user@notacme.com')).toBe(false);
    expect(isSafeDomain('user@acme.com.evil.com')).toBe(false);
  });

  it('returns false for strings without @', () => {
    expect(isSafeDomain('noemail')).toBe(false);
  });

  it('is case-insensitive on domain', () => {
    expect(isSafeDomain('user@ACME.COM')).toBe(true);
    expect(isSafeDomain('user@Example.Com')).toBe(true);
  });

  it('SAFE_DOMAINS has expected entries', () => {
    expect(SAFE_DOMAINS).toContain('acme.com');
    expect(SAFE_DOMAINS).toContain('example.com');
  });
});
