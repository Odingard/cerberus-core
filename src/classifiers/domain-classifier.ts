/**
 * Suspicious Domain/URL Classifier — Sub-classifier enhancing L3.
 *
 * Analyzes outbound destinations for risk indicators: disposable emails,
 * webhook services, IP addresses, URL shorteners, non-standard ports,
 * and social-engineering style domains (compliance/audit keyword patterns).
 */

import type { SuspiciousDestinationSignal } from '../types/signals.js';
import type { ToolCallContext } from '../types/context.js';
import type { DetectionSession } from '../engine/session.js';
import { extractDestination } from '../layers/l3-classifier.js';

/** Known webhook/exfiltration services. */
const EXFIL_SERVICES = [
  'webhook.site',
  'requestbin.com',
  'requestbin.net',
  'ngrok.io',
  'ngrok-free.app',
  'burpcollaborator.net',
  'pipedream.net',
  'hookbin.com',
  'requestcatcher.com',
  'beeceptor.com',
  'mockbin.org',
  'canarytokens.com',
  'interactsh.com',
  'oast.pro',
  'oast.me',
];

/** Known disposable email providers. */
const DISPOSABLE_EMAIL_DOMAINS = [
  'mailinator.com',
  'guerrillamail.com',
  'tempmail.com',
  'throwaway.email',
  'yopmail.com',
  'sharklasers.com',
  'guerrillamail.info',
  'trashmail.com',
  'temp-mail.org',
  'fakeinbox.com',
  'dispostable.com',
  'maildrop.cc',
  'spamgourmet.com',
  'trashmail.io',
];

/** Known URL shorteners. */
const URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'is.gd',
  'buff.ly',
  'ow.ly',
  'rebrand.ly',
  'shorturl.at',
  'cutt.ly',
];

/** IP address pattern. */
const IP_ADDRESS_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

/** Non-standard port in URL pattern. */
const NON_STANDARD_PORT_PATTERN = /:(\d{4,5})\b/;

/**
 * Action/compliance keywords that appear in social-engineering style domains.
 * Attackers register domains like audit-partner.io, compliance-verify.net,
 * data-transfer-service.com to make exfiltration destinations look legitimate.
 */
const SOCIAL_ENGINEERING_KEYWORDS = [
  'audit',
  'verify',
  'verification',
  'compliance',
  'validate',
  'validation',
  'backup',
  'transfer',
  'export',
  'submit',
  'forward',
  'sync',
  'review',
  'inspection',
  'report-service',
  'data-partner',
];

/**
 * TLDs commonly used for attacker infrastructure due to low registration cost.
 * Presence alone is not suspicious — combined with keyword patterns it is.
 */
const ATTACKER_PREFERRED_TLDS = ['.xyz', '.top', '.club', '.win', '.info', '.biz', '.tk', '.ml'];

/**
 * Detect social-engineering style domains: compliance/audit keyword in hostname
 * combined with a hyphenated structure or attacker-preferred TLD.
 *
 * Matches: audit-partner.io, compliance-verify.net, data-export.xyz
 * Does not match: acme.com, reports.internal.acme.com, compliance.gov
 */
export function hasSuspiciousKeywordPattern(domain: string): boolean {
  const lower = domain.toLowerCase();
  const hasKeyword = SOCIAL_ENGINEERING_KEYWORDS.some((kw) => lower.includes(kw));
  if (!hasKeyword) return false;

  // Keyword + hyphen adjacent = hallmark of social-engineering registered domain
  const hasHyphenWithKeyword = SOCIAL_ENGINEERING_KEYWORDS.some((kw) => {
    const idx = lower.indexOf(kw);
    if (idx === -1) return false;
    const before = lower[idx - 1];
    const after = lower[idx + kw.length];
    return before === '-' || after === '-';
  });

  // Keyword + suspicious TLD is also a strong signal
  const hasSuspiciousTld = ATTACKER_PREFERRED_TLDS.some((tld) => lower.endsWith(tld));

  return hasHyphenWithKeyword || hasSuspiciousTld;
}

/**
 * Extract domain from a destination string (email or URL).
 */
export function extractDomain(destination: string): string | null {
  // Email address
  const atIndex = destination.indexOf('@');
  if (atIndex > 0) {
    return destination.slice(atIndex + 1).toLowerCase();
  }

  // URL
  try {
    const url = new URL(destination);
    return url.hostname.toLowerCase();
  } catch {
    // Try adding protocol
    try {
      const url = new URL(`https://${destination}`);
      return url.hostname.toLowerCase();
    } catch {
      return null;
    }
  }
}

/**
 * Classify a destination for suspicious indicators.
 * Returns risk factors and overall risk level.
 */
export function classifyDestination(destination: string): {
  riskFactors: string[];
  domainRisk: 'low' | 'medium' | 'high';
} {
  const riskFactors: string[] = [];
  const domain = extractDomain(destination);

  if (!domain) {
    return { riskFactors: [], domainRisk: 'low' };
  }

  // Check disposable email
  if (DISPOSABLE_EMAIL_DOMAINS.some((d) => domain === d || domain.endsWith(`.${d}`))) {
    riskFactors.push('disposable_email');
  }

  // Check webhook/exfil services
  if (EXFIL_SERVICES.some((s) => domain === s || domain.endsWith(`.${s}`))) {
    riskFactors.push('exfil_service');
  }

  // Check URL shorteners
  if (URL_SHORTENERS.some((s) => domain === s)) {
    riskFactors.push('url_shortener');
  }

  // Check IP address as destination
  if (IP_ADDRESS_PATTERN.test(domain)) {
    riskFactors.push('ip_address');
  }

  // Check non-standard ports
  if (NON_STANDARD_PORT_PATTERN.test(destination)) {
    riskFactors.push('non_standard_port');
  }

  // Check social-engineering keyword patterns (catches audit-partner.io, compliance-verify.net)
  if (hasSuspiciousKeywordPattern(domain)) {
    riskFactors.push('social_engineering_domain');
  }

  // Determine risk level
  let domainRisk: 'low' | 'medium' | 'high' = 'low';
  if (riskFactors.length >= 2) {
    domainRisk = 'high';
  } else if (riskFactors.length === 1) {
    // Exfil services and disposable emails are high risk even alone
    if (
      riskFactors.includes('exfil_service') ||
      riskFactors.includes('disposable_email') ||
      riskFactors.includes('social_engineering_domain')
    ) {
      domainRisk = 'high';
    } else {
      domainRisk = 'medium';
    }
  }

  return { riskFactors, domainRisk };
}

/**
 * Classify the outbound destination for suspicious indicators.
 * Only runs for outbound tools (same gate as L3).
 */
export function classifyOutboundDomain(
  ctx: ToolCallContext,
  _session: DetectionSession,
  outboundTools: readonly string[],
): SuspiciousDestinationSignal | null {
  if (!outboundTools.includes(ctx.toolName)) {
    return null;
  }

  const destination = extractDestination(ctx.toolArguments);
  if (destination === 'unknown') {
    return null;
  }

  const { riskFactors, domainRisk } = classifyDestination(destination);
  if (riskFactors.length === 0) {
    return null;
  }

  return {
    layer: 'L3',
    signal: 'SUSPICIOUS_DESTINATION',
    turnId: ctx.turnId,
    destination,
    riskFactors,
    domainRisk,
    timestamp: ctx.timestamp,
  };
}
