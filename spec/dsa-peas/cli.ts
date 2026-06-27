#!/usr/bin/env node
/**
 * DSA-PEAS conformance validator — command-line entry.
 *
 * Reads a record, a JSON array of records, or a newline-delimited (JSONL)
 * stream — from a file or stdin — and reports AL2/AL3 conformance per record
 * plus the stream-wide blast-radius superset property. Exits non-zero if any
 * applicable check fails, so it drops straight into CI.
 *
 * Usage:
 *   dsa-peas-validate <records.json|records.jsonl|-> [--keyring keyring.json] [--json]
 *   npm run dsa-peas:validate -- spec/dsa-peas/examples/records.json \
 *     --keyring spec/dsa-peas/examples/keyring.json
 *
 * Standalone: imports only this package's validator and Node builtins — no
 * Cerberus internals, no SQLite, no third-party packages.
 */

import { readFileSync } from 'node:fs';
import { argv, exit, stdin } from 'node:process';
import {
  validateStream,
  type DsaPeasKeyring,
  type DsaPeasRecord,
  type DsaPeasTrustLevel,
  type RecordConformance,
  type StreamConformance,
} from './validator.js';

function die(message: string): never {
  console.error(`dsa-peas-validate: ${message}`);
  exit(2);
}

function readAllStdin(): string {
  return readFileSync(stdin.fd, 'utf8');
}

const TRUST_LEVELS: ReadonlySet<string> = new Set(['trusted', 'untrusted', 'unknown']);

function asString(obj: Record<string, unknown>, key: string, where: string): string {
  const v = obj[key];
  if (typeof v !== 'string') die(`${where}: "${key}" must be a string`);
  return v;
}

function asStringArray(obj: Record<string, unknown>, key: string, where: string): string[] {
  const v = obj[key];
  if (v === undefined) return [];
  if (!Array.isArray(v) || !v.every((x): x is string => typeof x === 'string')) {
    die(`${where}: "${key}" must be an array of strings`);
  }
  return v;
}

/** Coerce an untrusted JSON value into a DsaPeasRecord (fails loudly on bad shape). */
function toRecord(raw: unknown, where: string): DsaPeasRecord {
  if (typeof raw !== 'object' || raw === null) die(`${where}: record must be a JSON object`);
  const obj = raw as Record<string, unknown>;
  const trust = asString(obj, 'trustLevel', where);
  if (!TRUST_LEVELS.has(trust)) {
    die(`${where}: "trustLevel" must be trusted|untrusted|unknown, got "${trust}"`);
  }
  const ts = obj.timestamp;
  if (typeof ts !== 'number' || !Number.isFinite(ts)) die(`${where}: "timestamp" must be a number`);
  const base: DsaPeasRecord = {
    nodeId: asString(obj, 'nodeId', where),
    sessionId: asString(obj, 'sessionId', where),
    trustLevel: trust as DsaPeasTrustLevel,
    source: asString(obj, 'source', where),
    contentHash: asString(obj, 'contentHash', where),
    timestamp: ts,
    deps: asStringArray(obj, 'deps', where),
    commitment: asString(obj, 'commitment', where),
  };
  const author = typeof obj.author === 'string' && obj.author ? obj.author : undefined;
  const signature = typeof obj.signature === 'string' && obj.signature ? obj.signature : undefined;
  return {
    ...base,
    ...(author ? { author } : {}),
    ...(signature ? { signature } : {}),
  };
}

/** Parse the input as a single record, a JSON array, or JSONL. */
function parseRecords(text: string, where: string): DsaPeasRecord[] {
  const trimmed = text.trim();
  if (trimmed.length === 0) die(`${where}: empty input`);
  // Try whole-document JSON first (single object or array).
  try {
    const parsed: unknown = JSON.parse(trimmed);
    if (Array.isArray(parsed)) {
      return parsed.map((r, i) => toRecord(r, `${where}[${String(i)}]`));
    }
    return [toRecord(parsed, where)];
  } catch {
    // Fall back to JSONL: one record per non-blank line.
    const lines = trimmed.split('\n').filter((l) => l.trim().length > 0);
    return lines.map((line, i) => {
      let parsed: unknown;
      try {
        parsed = JSON.parse(line);
      } catch {
        return die(`${where}: line ${String(i + 1)} is not valid JSON`);
      }
      return toRecord(parsed, `${where}:line ${String(i + 1)}`);
    });
  }
}

function parseKeyring(text: string, where: string): DsaPeasKeyring {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return die(`${where}: not valid JSON`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    die(`${where}: keyring must be a JSON object of { author: spkiPem }`);
  }
  const out: Record<string, string> = {};
  for (const [author, pem] of Object.entries(parsed)) {
    if (typeof pem !== 'string') die(`${where}: key for "${author}" must be a PEM string`);
    out[author] = pem;
  }
  return out;
}

function tick(pass: boolean): string {
  return pass ? 'PASS' : 'FAIL';
}

function printRecord(rc: RecordConformance): void {
  const al3 = rc.al3.applicable ? tick(rc.al3.pass) : '  — ';
  console.log(`  ${rc.nodeId.padEnd(28)}  AL2 ${tick(rc.al2.pass)}   AL3 ${al3}`);
  for (const level of [rc.al2, rc.al3]) {
    if (!level.applicable) continue;
    for (const c of level.checks) {
      if (!c.pass) {
        console.log(`      ✗ ${level.level}/${c.name}${c.detail ? ` (${c.detail})` : ''}`);
      }
    }
  }
}

function printReport(report: StreamConformance): void {
  console.log(
    `\nDSA-PEAS conformance — ${String(report.recordCount)} record(s), ` +
      `${String(report.signedCount)} signed (AL3)\n`,
  );
  for (const rc of report.records) {
    printRecord(rc);
  }
  console.log('\nSTREAM');
  console.log(`  AL2 (commitment + mutation)     : ${tick(report.al2Pass)}`);
  console.log(
    `  AL3 (authorship + forgery)      : ${
      report.signedCount > 0 ? tick(report.al3Pass) : 'n/a (no signed records)'
    }`,
  );
  console.log(`  blast-radius superset (no FN)   : ${tick(report.blastRadiusSuperset)}`);
  if (report.blastRadiusLeak) {
    const l = report.blastRadiusLeak;
    console.log(`      ✗ ${l.escaped} escapes B(${l.poison}) via ${l.via}`);
  }
  console.log(`\nOVERALL: ${tick(report.pass)}`);
}

function main(): void {
  const args = argv.slice(2);
  const asJson = args.includes('--json');
  const keyringIdx = args.indexOf('--keyring');
  const keyringPath = keyringIdx >= 0 ? args[keyringIdx + 1] : undefined;
  if (keyringIdx >= 0 && !keyringPath) die('--keyring requires a path');
  const positional = args.filter(
    (a, i) => !a.startsWith('--') && i !== keyringIdx + 1 && a !== '--json',
  );
  const input = positional[0];
  if (!input) {
    die('usage: dsa-peas-validate <records.json|.jsonl|-> [--keyring keyring.json] [--json]');
  }

  const recordsText = input === '-' ? readAllStdin() : readFileSync(input, 'utf8');
  const records = parseRecords(recordsText, input === '-' ? 'stdin' : input);
  const keyring: DsaPeasKeyring = keyringPath
    ? parseKeyring(readFileSync(keyringPath, 'utf8'), keyringPath)
    : {};

  const report = validateStream(records, keyring);

  if (asJson) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    printReport(report);
  }
  exit(report.pass ? 0 : 1);
}

main();
