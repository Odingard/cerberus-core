#!/usr/bin/env tsx
/* eslint-disable no-console */
/**
 * Validation Protocol CLI — single command to run the full scientific validation.
 *
 * Usage:
 *   npx tsx harness/validation/cli.ts                              # Full protocol (all providers)
 *   npx tsx harness/validation/cli.ts --provider openai             # Single provider
 *   npx tsx harness/validation/cli.ts --model gpt-4o-mini           # Specific model
 *   npx tsx harness/validation/cli.ts --trials 10 --control-trials 20
 *   npx tsx harness/validation/cli.ts --payloads DI-001,DI-002,SE-001
 *   npx tsx harness/validation/cli.ts --prompt safety
 */

import { resolve } from 'node:path';
import { readFileSync, existsSync } from 'node:fs';
import { runValidationProtocol } from './runner.js';
import { printReportSummary, writeMarkdownReport } from './reporter.js';
import { runProviderPreflightChecks } from './preflight.js';
import type { SystemPromptId } from '../runner.js';
import { PAYLOADS } from '../payloads.js';

// ── Env Loading ──────────────────────────────────────────────────

const PROVIDER_ENV_VARS: Record<string, string> = {
  openai: 'OPENAI_API_KEY',
  anthropic: 'ANTHROPIC_API_KEY',
  google: 'GOOGLE_API_KEY',
};

/**
 * Load .env file from project root if it exists.
 * Simple key=value parser — no interpolation, no multiline.
 */
function loadEnvFile(): void {
  const envPath = resolve(process.cwd(), '.env');
  if (!existsSync(envPath)) return;

  const content = readFileSync(envPath, 'utf-8');
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIndex = trimmed.indexOf('=');
    if (eqIndex === -1) continue;
    const key = trimmed.slice(0, eqIndex).trim();
    const value = trimmed.slice(eqIndex + 1).trim();
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

/**
 * Fail fast if required API keys are missing for the selected providers.
 */
function assertApiKeys(providers: readonly ProviderConfig[]): void {
  const missing: string[] = [];
  for (const { provider } of providers) {
    const envVar = PROVIDER_ENV_VARS[provider];
    if (envVar && !process.env[envVar]) {
      missing.push(`  ${provider}: ${envVar} is not set`);
    }
  }
  if (missing.length > 0) {
    // eslint-disable-next-line no-console
    console.error('\nMissing API keys:\n' + missing.join('\n'));
    // eslint-disable-next-line no-console
    console.error(
      '\nEither:\n  1. Create a .env file in the project root with the keys\n  2. Export them: export OPENAI_API_KEY=sk-...\n',
    );
    process.exit(1);
  }
}

// ── Arg Parsing ─────────────────────────────────────────────────

interface CliArgs {
  provider?: string;
  model?: string;
  trials: number;
  controlTrials: number;
  prompt: SystemPromptId;
  payloads?: string[];
  outputDir: string;
  delay: number;
  detect: boolean;
  skipPreflight: boolean;
}

function parseArgs(argv: string[]): CliArgs {
  const args: CliArgs = {
    trials: 5,
    controlTrials: 10,
    prompt: 'permissive',
    outputDir: resolve(process.cwd(), 'harness', 'validation-traces'),
    delay: 1000,
    detect: false,
    skipPreflight: false,
  };

  for (let i = 2; i < argv.length; i++) {
    const arg = argv[i];
    const next = argv[i + 1];

    switch (arg) {
      case '--provider':
        args.provider = next;
        i++;
        break;
      case '--model':
        args.model = next;
        i++;
        break;
      case '--trials':
        args.trials = parseInt(next, 10);
        i++;
        break;
      case '--control-trials':
        args.controlTrials = parseInt(next, 10);
        i++;
        break;
      case '--prompt':
        args.prompt = next as SystemPromptId;
        i++;
        break;
      case '--payloads':
        args.payloads = next.split(',');
        i++;
        break;
      case '--output-dir':
        args.outputDir = resolve(next);
        i++;
        break;
      case '--delay':
        args.delay = parseInt(next, 10);
        i++;
        break;
      case '--detect':
        args.detect = true;
        break;
      case '--skip-preflight':
        args.skipPreflight = true;
        break;
      case '--help':
        printHelp();
        process.exit(0);
        break;
      default:
        console.error(`Unknown argument: ${arg}`);
        printHelp();
        process.exit(1);
    }
  }

  return args;
}

function printHelp(): void {
  console.log(`
Cerberus Validation Protocol — Scientific Attack Validation

Usage:
  npx tsx harness/validation/cli.ts [options]

Options:
  --provider <name>       Provider to test: openai, anthropic, google (default: all three)
  --model <id>            Model ID (default: auto-detected per provider)
  --trials <n>            Trials per payload per provider (default: 5)
  --control-trials <n>    Control trials per provider (default: 10)
  --prompt <id>           System prompt: permissive, neutral, restrictive, safety (default: permissive)
  --payloads <ids>        Comma-separated payload IDs (default: all 55)
  --output-dir <path>     Output directory (default: harness/validation-traces/)
  --delay <ms>            Delay between runs in ms (default: 1000)
  --detect                Enable Cerberus detection validation (observe-only)
  --skip-preflight        Skip provider connectivity/auth preflight checks
  --help                  Show this help

Examples:
  npx tsx harness/validation/cli.ts --provider openai --model gpt-4o-mini --trials 3
  npx tsx harness/validation/cli.ts --payloads DI-001,SE-001 --prompt safety
  npx tsx harness/validation/cli.ts --trials 10 --control-trials 20
`);
}

// ── Provider Resolution ─────────────────────────────────────────

interface ProviderConfig {
  model: string;
  provider: string;
}

const DEFAULT_PROVIDERS: readonly ProviderConfig[] = [
  { model: 'gpt-4o-mini', provider: 'openai' },
  { model: 'claude-sonnet-4-20250514', provider: 'anthropic' },
  { model: 'gemini-2.5-flash', provider: 'google' },
];

function resolveProviders(args: CliArgs): ProviderConfig[] {
  if (args.model) {
    const provider = args.provider ?? detectProviderFromModel(args.model);
    return [{ model: args.model, provider }];
  }

  if (args.provider) {
    const defaultModel = DEFAULT_PROVIDERS.find((p) => p.provider === args.provider);
    if (!defaultModel) {
      console.error(`Unknown provider: ${args.provider}. Use: openai, anthropic, google`);
      process.exit(1);
    }
    return [defaultModel];
  }

  return [...DEFAULT_PROVIDERS];
}

function detectProviderFromModel(model: string): string {
  if (model.startsWith('claude-')) return 'anthropic';
  if (model.startsWith('gemini-')) return 'google';
  return 'openai';
}

// ── Main ────────────────────────────────────────────────────────

async function main(): Promise<void> {
  loadEnvFile();

  const args = parseArgs(process.argv);
  const providers = resolveProviders(args);

  assertApiKeys(providers);

  if (!args.skipPreflight) {
    console.log('  Running provider preflight checks...\n');
    const preflightResults = await runProviderPreflightChecks(providers);
    const failures = preflightResults.filter((result) => !result.ok);

    for (const result of preflightResults) {
      if (result.ok) {
        console.log(`  ✓ ${result.provider} (${result.model}) preflight passed`);
      } else {
        console.log(`  ✗ ${result.provider} (${result.model}) preflight failed`);
        console.log(`    ${result.error}`);
      }
    }
    console.log('');

    if (failures.length > 0) {
      console.error('Validation aborted: provider preflight checks failed.');
      process.exit(1);
    }
  }

  console.log('\n╔══════════════════════════════════════════════════════════╗');
  console.log('║         CERBERUS VALIDATION PROTOCOL                     ║');
  console.log('╚══════════════════════════════════════════════════════════╝\n');

  const payloadCount = args.payloads ? args.payloads.length : PAYLOADS.length;
  const totalRuns =
    providers.length * payloadCount * args.trials + providers.length * args.controlTrials;
  const estimatedMinutes = Math.ceil((totalRuns * (args.delay + 3000)) / 60000); // ~3s per API call + delay

  console.log(`  Providers:      ${providers.map((p) => `${p.provider} (${p.model})`).join(', ')}`);
  console.log(`  Trials/payload: ${String(args.trials)}`);
  console.log(`  Control trials: ${String(args.controlTrials)}/provider`);
  console.log(`  System prompt:  ${args.prompt}`);
  if (args.payloads) {
    console.log(`  Payloads:       ${args.payloads.join(', ')}`);
  } else {
    console.log(`  Payloads:       all ${String(PAYLOADS.length)}`);
  }
  if (args.detect) {
    console.log(`  Detection:      ENABLED (observe-only, alertMode=log, authorized: acme.com)`);
  }
  console.log(`  Total runs:     ${String(totalRuns)}`);
  console.log(`  Est. time:      ~${String(estimatedMinutes)} minutes`);
  console.log(`  Output:         ${args.outputDir}`);
  console.log('');

  const report = await runValidationProtocol({
    providers,
    trialsPerPayload: args.trials,
    controlTrialsPerProvider: args.controlTrials,
    systemPromptId: args.prompt,
    outputDir: args.outputDir,
    delayBetweenRunsMs: args.delay,
    ...(args.payloads ? { payloadIds: args.payloads } : {}),
    ...(args.detect ? { detectMode: true } : {}),
    onProgress: (progress) => {
      const phase = progress.phase === 'control' ? 'CTRL' : 'TREAT';
      const payload = progress.payloadId ? ` ${progress.payloadId}` : '';
      const trial =
        progress.trialIndex !== undefined ? ` trial ${String(progress.trialIndex + 1)}` : '';
      process.stdout.write(
        `\r  [${phase}] ${progress.provider} ${String(progress.current)}/${String(progress.total)}${payload}${trial}    `,
      );
    },
  });

  console.log('\n');

  // Check for errors
  const allErrorCounts =
    Object.values(report.treatmentResults)
      .map((s) => s.outcomes.error)
      .reduce((a, b) => a + b, 0) +
    Object.values(report.controlResults)
      .map((s) => s.outcomes.error)
      .reduce((a, b) => a + b, 0);

  if (allErrorCounts > 0) {
    // eslint-disable-next-line no-console
    console.log(
      `  ⚠ ${String(allErrorCounts)}/${String(totalRuns)} runs errored — check API keys and network connectivity.\n`,
    );
  }

  // Print summary to console
  printReportSummary(report);

  // Write markdown report
  const mdPath = writeMarkdownReport(report, args.outputDir);
  console.log(`  Markdown report: ${mdPath}`);
  console.log(`  JSON report:     ${args.outputDir}/validation-report-*.json\n`);
}

main().catch((err: unknown) => {
  if (err instanceof Error && err.message === 'VALIDATION_EXIT') {
    // Already printed by assertApiKeys
  } else {
    // eslint-disable-next-line no-console
    console.error('Validation protocol failed:', err);
  }
  process.exit(1);
});
