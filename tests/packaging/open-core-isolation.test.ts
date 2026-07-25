/**
 * Open-core isolation invariant.
 *
 * `@cerberus-ai/core` is the public, MIT-licensed open tier. It must never
 * depend on — or import from — the licensed `@cerberus-ai/enterprise` package.
 * Enterprise capabilities (durable SQLite ledger, blast-radius B(p), AL3
 * signing, Verdict-Weight intelligence, the enforcement proxy) are referenced
 * only in documentation comments, never wired in at build/runtime.
 *
 * This test walks the shipped source tree and fails on any real import of the
 * enterprise package, so a future refactor cannot silently pull paid code into
 * the open tarball.
 */
import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const SRC = fileURLToPath(new URL('../../src', import.meta.url));

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      out.push(...tsFiles(full));
    } else if (entry.endsWith('.ts')) {
      out.push(full);
    }
  }
  return out;
}

// Matches a real ESM/CJS import of the enterprise package, e.g.
//   import { x } from '@cerberus-ai/enterprise'
//   import('@cerberus-ai/enterprise/graph/durable-ledger.js')
//   require('@cerberus-ai/enterprise')
// but NOT a mention inside a comment or string used for documentation.
const ENTERPRISE_IMPORT =
  /(?:^|\n)\s*(?:import|export)\b[^\n]*?\bfrom\s*['"]@cerberus-ai\/enterprise|['"]@cerberus-ai\/enterprise['"]\s*\)|import\s*\(\s*['"]@cerberus-ai\/enterprise/;

describe('open-core isolation', () => {
  const files = tsFiles(SRC);

  it('finds source files to scan', () => {
    expect(files.length).toBeGreaterThan(0);
  });

  it('no src file imports @cerberus-ai/enterprise', () => {
    const offenders: string[] = [];
    for (const file of files) {
      const body = readFileSync(file, 'utf8');
      // Strip line + block comments so a documentation reference to the
      // enterprise package (which is expected and encouraged) does not trip us.
      const codeOnly = body
        .replace(/\/\*[\s\S]*?\*\//g, '')
        .replace(/(^|[^:])\/\/[^\n]*/g, '$1');
      if (ENTERPRISE_IMPORT.test(codeOnly)) {
        offenders.push(file.slice(SRC.length + 1));
      }
    }
    expect(offenders, `open core must not import enterprise: ${offenders.join(', ')}`).toEqual([]);
  });
});
