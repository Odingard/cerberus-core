/**
 * Stress Test Analyzer — compares harness runs and computes per-payload statistics.
 *
 * Usage:
 *   npx tsx harness/analyze.ts <summary-file>                     # single run analysis
 *   npx tsx harness/analyze.ts <summary-A> <summary-B>            # compare two runs
 *   npx tsx harness/analyze.ts --traces-dir <dir>                 # analyze all traces in dir
 */

import { readFileSync, readdirSync } from 'node:fs';
import { resolve } from 'node:path';
import type {
  RunSummary,
  StressSummary,
  ExecutionTrace,
  PayloadTrialStats,
  PayloadCategory,
} from './types.js';

// ── File Loading ──────────────────────────────────────────────────

/** Type guard: is this a StressSummary (has perPayload field)? */
export function isStressSummary(summary: RunSummary | StressSummary): summary is StressSummary {
  return 'perPayload' in summary && Array.isArray(summary.perPayload);
}

/** Load and parse a summary JSON file. */
export function loadSummary(filePath: string): RunSummary | StressSummary {
  const content = readFileSync(filePath, 'utf-8');
  return JSON.parse(content) as RunSummary | StressSummary;
}

/** Load all valid trace files from a directory. */
export function loadTracesFromDir(dir: string): ExecutionTrace[] {
  const files = readdirSync(dir).filter(
    (f) =>
      f.endsWith('.json') &&
      !f.startsWith('_summary') &&
      !f.startsWith('_stress-summary') &&
      !f.includes('ERROR'),
  );

  const traces: ExecutionTrace[] = [];
  for (const file of files) {
    try {
      const content = readFileSync(resolve(dir, file), 'utf-8');
      const parsed = JSON.parse(content) as Record<string, unknown>;
      if (parsed['schemaVersion'] === '1.0.0' && parsed['payload']) {
        traces.push(parsed as unknown as ExecutionTrace);
      }
    } catch {
      // Skip unparseable files
    }
  }
  return traces;
}

// ── Statistics ────────────────────────────────────────────────────

/** Compute per-payload statistics from a set of traces. */
export function computePerPayloadStats(traces: readonly ExecutionTrace[]): PayloadTrialStats[] {
  const grouped = new Map<
    string,
    {
      category: PayloadCategory;
      successes: number;
      partials: number;
      failures: number;
      errors: number;
      total: number;
    }
  >();

  for (const trace of traces) {
    const id = trace.payload.id;
    if (!grouped.has(id)) {
      grouped.set(id, {
        category: trace.payload.category,
        successes: 0,
        partials: 0,
        failures: 0,
        errors: 0,
        total: 0,
      });
    }
    const stats = grouped.get(id)!;
    stats.total++;
    switch (trace.labels.outcome) {
      case 'success':
        stats.successes++;
        break;
      case 'partial':
        stats.partials++;
        break;
      case 'failure':
        stats.failures++;
        break;
      case 'error':
        stats.errors++;
        break;
    }
  }

  const result: PayloadTrialStats[] = [];
  for (const [payloadId, stats] of grouped) {
    result.push({
      payloadId,
      category: stats.category,
      trials: stats.total,
      successes: stats.successes,
      partials: stats.partials,
      failures: stats.failures,
      errors: stats.errors,
      successRate: stats.total > 0 ? stats.successes / stats.total : 0,
    });
  }

  return result.sort((a, b) => a.payloadId.localeCompare(b.payloadId));
}

// ── Formatting ────────────────────────────────────────────────────

/** Format a percentage for display. */
function pct(rate: number): string {
  return `${(rate * 100).toFixed(0)}%`;
}

/** Pad a string to a fixed width. */
function pad(str: string, width: number): string {
  return str.padEnd(width);
}

/** Right-align a string to a fixed width. */
function rpad(str: string, width: number): string {
  return str.padStart(width);
}

// ── Printers ──────────────────────────────────────────────────────

/** Print a single summary to console. */
export function printSingleRun(summary: RunSummary | StressSummary): void {
  // eslint-disable-next-line no-console
  console.log('\n=== Harness Run Summary ===\n');
  // eslint-disable-next-line no-console
  console.log(`Total runs:    ${String(summary.totalRuns)}`);
  // eslint-disable-next-line no-console
  console.log(`Success:       ${String(summary.successCount)} (${pct(summary.successRate)})`);
  // eslint-disable-next-line no-console
  console.log(`Partial:       ${String(summary.partialCount)}`);
  // eslint-disable-next-line no-console
  console.log(`Failure:       ${String(summary.failureCount)}`);
  // eslint-disable-next-line no-console
  console.log(`Error:         ${String(summary.errorCount)}`);
  // eslint-disable-next-line no-console
  console.log(`Completed:     ${summary.completedAt}`);

  // Category breakdown
  // eslint-disable-next-line no-console
  console.log('\n--- Category Breakdown ---\n');
  // eslint-disable-next-line no-console
  console.log(
    `${pad('Category', 22)} | ${rpad('Total', 5)} | ${rpad('Success', 7)} | ${rpad('Rate', 5)}`,
  );
  // eslint-disable-next-line no-console
  console.log(`${'─'.repeat(22)}─┼─${'─'.repeat(5)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(5)}`);
  for (const [cat, stats] of Object.entries(summary.byCategory)) {
    // eslint-disable-next-line no-console
    console.log(
      `${pad(cat, 22)} | ${rpad(String(stats.total), 5)} | ${rpad(String(stats.successes), 7)} | ${rpad(pct(stats.rate), 5)}`,
    );
  }

  // Per-payload breakdown (stress summary only)
  if (isStressSummary(summary) && summary.perPayload.length > 0) {
    // eslint-disable-next-line no-console
    console.log(
      `\n--- Per-Payload Breakdown (${String(summary.trialsPerPayload)} trials, prompt: ${summary.systemPromptId}) ---\n`,
    );
    // eslint-disable-next-line no-console
    console.log(
      `${pad('Payload', 10)} | ${rpad('Trials', 6)} | ${rpad('Success', 7)} | ${rpad('Partial', 7)} | ${rpad('Failure', 7)} | ${rpad('Rate', 5)}`,
    );
    // eslint-disable-next-line no-console
    console.log(
      `${'─'.repeat(10)}─┼─${'─'.repeat(6)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(5)}`,
    );

    for (const ps of summary.perPayload) {
      // eslint-disable-next-line no-console
      console.log(
        `${pad(ps.payloadId, 10)} | ${rpad(String(ps.trials), 6)} | ${rpad(String(ps.successes), 7)} | ${rpad(String(ps.partials), 7)} | ${rpad(String(ps.failures), 7)} | ${rpad(pct(ps.successRate), 5)}`,
      );
    }

    // eslint-disable-next-line no-console
    console.log(`\nMean success rate: ${pct(summary.meanSuccessRate)}`);
    // eslint-disable-next-line no-console
    console.log(`Variance:         ${summary.successRateVariance.toFixed(4)}`);
  }
}

/** Print a comparison between two summaries. */
export function printComparison(
  a: RunSummary | StressSummary,
  b: RunSummary | StressSummary,
): void {
  // eslint-disable-next-line no-console
  console.log('\n=== Run Comparison ===\n');

  const deltaRate = b.successRate - a.successRate;
  const deltaSign = deltaRate >= 0 ? '+' : '';

  // eslint-disable-next-line no-console
  console.log(
    `${pad('Metric', 20)} | ${rpad('Run A', 10)} | ${rpad('Run B', 10)} | ${rpad('Delta', 10)}`,
  );
  // eslint-disable-next-line no-console
  console.log(`${'─'.repeat(20)}─┼─${'─'.repeat(10)}─┼─${'─'.repeat(10)}─┼─${'─'.repeat(10)}`);
  // eslint-disable-next-line no-console
  console.log(
    `${pad('Total runs', 20)} | ${rpad(String(a.totalRuns), 10)} | ${rpad(String(b.totalRuns), 10)} | ${rpad(String(b.totalRuns - a.totalRuns), 10)}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `${pad('Success rate', 20)} | ${rpad(pct(a.successRate), 10)} | ${rpad(pct(b.successRate), 10)} | ${rpad(`${deltaSign}${pct(deltaRate)}`, 10)}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `${pad('Successes', 20)} | ${rpad(String(a.successCount), 10)} | ${rpad(String(b.successCount), 10)} | ${rpad(String(b.successCount - a.successCount), 10)}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `${pad('Failures', 20)} | ${rpad(String(a.failureCount), 10)} | ${rpad(String(b.failureCount), 10)} | ${rpad(String(b.failureCount - a.failureCount), 10)}`,
  );

  // Category comparison
  // eslint-disable-next-line no-console
  console.log('\n--- Category Comparison ---\n');
  // eslint-disable-next-line no-console
  console.log(
    `${pad('Category', 22)} | ${rpad('Rate A', 8)} | ${rpad('Rate B', 8)} | ${rpad('Delta', 8)}`,
  );
  // eslint-disable-next-line no-console
  console.log(`${'─'.repeat(22)}─┼─${'─'.repeat(8)}─┼─${'─'.repeat(8)}─┼─${'─'.repeat(8)}`);

  const allCats = new Set([...Object.keys(a.byCategory), ...Object.keys(b.byCategory)]);
  for (const cat of allCats) {
    const aStats = (a.byCategory as Record<string, { rate: number }>)[cat];
    const bStats = (b.byCategory as Record<string, { rate: number }>)[cat];
    const aRate = aStats?.rate ?? 0;
    const bRate = bStats?.rate ?? 0;
    const d = bRate - aRate;
    const sign = d >= 0 ? '+' : '';
    // eslint-disable-next-line no-console
    console.log(
      `${pad(cat, 22)} | ${rpad(pct(aRate), 8)} | ${rpad(pct(bRate), 8)} | ${rpad(`${sign}${pct(d)}`, 8)}`,
    );
  }
}

/** Print analysis of raw traces grouped by payload and prompt. */
export function printTraceAnalysis(traces: readonly ExecutionTrace[]): void {
  // eslint-disable-next-line no-console
  console.log(`\n=== Trace Analysis (${String(traces.length)} traces) ===\n`);

  const stats = computePerPayloadStats(traces);

  // eslint-disable-next-line no-console
  console.log(
    `${pad('Payload', 10)} | ${pad('Category', 22)} | ${rpad('Runs', 4)} | ${rpad('Success', 7)} | ${rpad('Rate', 5)}`,
  );
  // eslint-disable-next-line no-console
  console.log(
    `${'─'.repeat(10)}─┼─${'─'.repeat(22)}─┼─${'─'.repeat(4)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(5)}`,
  );

  for (const ps of stats) {
    // eslint-disable-next-line no-console
    console.log(
      `${pad(ps.payloadId, 10)} | ${pad(ps.category, 22)} | ${rpad(String(ps.trials), 4)} | ${rpad(String(ps.successes), 7)} | ${rpad(pct(ps.successRate), 5)}`,
    );
  }

  // Group by system prompt if available
  const byPrompt = new Map<string, ExecutionTrace[]>();
  for (const trace of traces) {
    const promptId = 'systemPromptId' in trace.config ? trace.config.systemPromptId : 'unknown';
    if (!byPrompt.has(promptId)) byPrompt.set(promptId, []);
    byPrompt.get(promptId)!.push(trace);
  }

  if (byPrompt.size > 1) {
    // eslint-disable-next-line no-console
    console.log('\n--- By System Prompt ---\n');
    // eslint-disable-next-line no-console
    console.log(
      `${pad('Prompt', 15)} | ${rpad('Runs', 4)} | ${rpad('Success', 7)} | ${rpad('Rate', 5)}`,
    );
    // eslint-disable-next-line no-console
    console.log(`${'─'.repeat(15)}─┼─${'─'.repeat(4)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(5)}`);

    for (const [promptId, promptTraces] of byPrompt) {
      const successes = promptTraces.filter((t) => t.labels.outcome === 'success').length;
      const rate = promptTraces.length > 0 ? successes / promptTraces.length : 0;
      // eslint-disable-next-line no-console
      console.log(
        `${pad(promptId, 15)} | ${rpad(String(promptTraces.length), 4)} | ${rpad(String(successes), 7)} | ${rpad(pct(rate), 5)}`,
      );
    }
  }

  // Group by model/provider
  const byModel = new Map<string, ExecutionTrace[]>();
  for (const trace of traces) {
    const model = trace.config.model ?? 'unknown';
    if (!byModel.has(model)) byModel.set(model, []);
    byModel.get(model)!.push(trace);
  }

  if (byModel.size > 1) {
    // eslint-disable-next-line no-console
    console.log('\n--- By Model ---\n');
    // eslint-disable-next-line no-console
    console.log(
      `${pad('Model', 25)} | ${rpad('Runs', 4)} | ${rpad('Success', 7)} | ${rpad('Rate', 5)}`,
    );
    // eslint-disable-next-line no-console
    console.log(`${'─'.repeat(25)}─┼─${'─'.repeat(4)}─┼─${'─'.repeat(7)}─┼─${'─'.repeat(5)}`);

    for (const [model, modelTraces] of byModel) {
      const successes = modelTraces.filter((t) => t.labels.outcome === 'success').length;
      const rate = modelTraces.length > 0 ? successes / modelTraces.length : 0;
      // eslint-disable-next-line no-console
      console.log(
        `${pad(model, 25)} | ${rpad(String(modelTraces.length), 4)} | ${rpad(String(successes), 7)} | ${rpad(pct(rate), 5)}`,
      );
    }
  }

  // Token usage summary
  const totalTokens = traces.reduce((sum, t) => sum + t.tokenUsage.totalTokens, 0);
  const avgTokens = traces.length > 0 ? Math.round(totalTokens / traces.length) : 0;
  const avgDuration =
    traces.length > 0
      ? Math.round(traces.reduce((sum, t) => sum + t.durationMs, 0) / traces.length)
      : 0;

  // eslint-disable-next-line no-console
  console.log(`\nTotal tokens:     ${String(totalTokens)}`);
  // eslint-disable-next-line no-console
  console.log(`Avg tokens/run:   ${String(avgTokens)}`);
  // eslint-disable-next-line no-console
  console.log(`Avg duration/run: ${String(avgDuration)}ms`);
}

// ── CLI Entry Point ──────────────────────────────────────────────

function main(): void {
  const args = process.argv.slice(2);

  // --traces-dir mode
  const tracesDirIndex = args.indexOf('--traces-dir');
  if (tracesDirIndex !== -1 && args[tracesDirIndex + 1]) {
    const dir = resolve(args[tracesDirIndex + 1]);
    const traces = loadTracesFromDir(dir);
    printTraceAnalysis(traces);
    return;
  }

  // File argument mode
  const files = args.filter((a) => !a.startsWith('--'));

  if (files.length === 0) {
    // eslint-disable-next-line no-console
    console.log('Usage:');
    // eslint-disable-next-line no-console
    console.log('  npx tsx harness/analyze.ts <summary-file>              # single run');
    // eslint-disable-next-line no-console
    console.log('  npx tsx harness/analyze.ts <summary-A> <summary-B>     # compare');
    // eslint-disable-next-line no-console
    console.log('  npx tsx harness/analyze.ts --traces-dir <dir>           # raw traces');
    process.exit(1);
  }

  if (files.length === 1) {
    const summary = loadSummary(resolve(files[0]));
    printSingleRun(summary);
  } else if (files.length >= 2) {
    const a = loadSummary(resolve(files[0]));
    const b = loadSummary(resolve(files[1]));
    printComparison(a, b);
  }
}

const isMain = process.argv[1]?.endsWith('analyze.ts') || process.argv[1]?.endsWith('analyze.js');
if (isMain) {
  try {
    main();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('[analyze] Error:', err);
    process.exit(1);
  }
}
