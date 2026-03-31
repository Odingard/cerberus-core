/**
 * Memory Tracking Example (L4)
 *
 * Demonstrates Cerberus detecting cross-session memory contamination:
 * 1. Session A: An untrusted tool writes contaminated data to memory
 * 2. reset() simulates a new session
 * 3. Session B: Reading the contaminated memory triggers L4
 *
 * Run: npx tsx examples/memory-tracking.ts
 *
 * Note: This example uses relative imports for development.
 * In your project, use: import { guard } from '@cerberus-ai/core';
 */

import { guard } from '../src/index.js';
import type { CerberusConfig, MemoryToolConfig } from '../src/index.js';

// ── Simulated Memory Store ───────────────────────────────────────

const memoryStore = new Map<string, string>();

const executors = {
  writeMemory: (args: Record<string, unknown>): Promise<string> => {
    const key = String(args.key);
    const value = String(args.value);
    memoryStore.set(key, value);
    return Promise.resolve('ok');
  },

  readMemory: (args: Record<string, unknown>): Promise<string> => {
    const key = String(args.key);
    return Promise.resolve(memoryStore.get(key) ?? '');
  },
};

// ── Configuration ────────────────────────────────────────────────

const config: CerberusConfig = {
  alertMode: 'interrupt',
  threshold: 1,
  memoryTracking: true,
  trustOverrides: [{ toolName: 'writeMemory', trustLevel: 'untrusted' }],
  onAssessment: ({ turnId, score, action }) => {
    console.log(`  [Assessment] ${turnId}: score=${String(score)}/4, action=${action}`);
  },
};

const memoryTools: readonly MemoryToolConfig[] = [
  { toolName: 'writeMemory', operation: 'write' },
  { toolName: 'readMemory', operation: 'read' },
];

// ── Run ──────────────────────────────────────────────────────────

async function main(): Promise<void> {
  console.log('=== Cerberus Memory Tracking (L4) Example ===\n');

  const result = guard(executors, config, [], { memoryTools });

  console.log(`Session A: ${result.session.sessionId}`);
  console.log(`Graph created: ${String(result.graph !== undefined)}`);
  console.log(`Ledger created: ${String(result.ledger !== undefined)}\n`);

  // Session A: Write contaminated data via untrusted source
  console.log('Session A: Writing contaminated data to memory...');
  await result.executors.writeMemory({
    key: 'user-preferences',
    value: 'injected malicious payload from external source',
  });
  console.log(`  Graph size: ${String(result.graph!.size())} node(s)`);
  console.log(
    `  Ledger history: ${String(result.ledger!.getNodeHistory('user-preferences').length)} record(s)\n`,
  );

  // Reset simulates a new session
  console.log('--- reset() → new session ---\n');
  result.reset();
  console.log(`Session B: ${result.session.sessionId}`);
  console.log(`Graph persisted: ${String(result.graph!.size())} node(s) (survives reset)\n`);

  // Session B: Read contaminated memory → triggers L4
  console.log('Session B: Reading contaminated memory node...');
  await result.executors.readMemory({ key: 'user-preferences' });

  console.log('\n=== Assessment Summary ===');
  for (const a of result.assessments) {
    const v = a.vector;
    console.log(
      `  ${a.turnId}: L1=${String(v.l1)} L2=${String(v.l2)} L3=${String(v.l3)} L4=${String(v.l4)} → score=${String(a.score)}, action=${a.action}`,
    );
  }

  result.destroy();
}

main().catch(console.error);
