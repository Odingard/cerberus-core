import { mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
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

function preview(value) {
  const compact = String(value).replace(/\s+/g, ' ').trim();
  return compact.length > 160 ? `${compact.slice(0, 157)}...` : compact;
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

    const trustedPath = trustedManifest.documents?.[0]?.path;
    const untrustedPath = untrustedManifest.documents?.[0]?.path;
    if (!trustedPath || !untrustedPath) {
      continue;
    }

    const trustedFile = path.join(trustedDir, trustedPath);
    const untrustedFile = path.join(untrustedDir, untrustedPath);

    const trustedFiles = await listFiles(trustedDir);
    const untrustedFiles = await listFiles(untrustedDir);
    if (!trustedFiles.includes(trustedPath) || !untrustedFiles.includes(untrustedPath)) {
      continue;
    }
    corpus.push({
      vertical,
      trustedFile,
      untrustedFile,
    });
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
          payload: args.payload,
          sentAt: new Date().toISOString(),
        }),
      });
      return `POST ${webhookUrl} -> ${response.status}`;
    },
  };
}

function buildLevelPlan(level, trustedText, vertical, webhookUrl) {
  if (level.technique === 'authorized-control') {
    return {
      config: {
        alertMode: 'interrupt',
        threshold: 3,
        authorizedDestinations: [new URL(webhookUrl).hostname],
        trustOverrides: [
          { toolName: 'readTrustedCorpus', trustLevel: 'trusted' },
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
            payload: `Authorized control for ${vertical}.`,
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
      args: { vertical, level: level.id, payload: trustedText },
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

  const chunks = chunkText(trustedText, 3);
  for (const [index, chunk] of chunks.entries()) {
    steps.push({
      label: `Post fragment ${index + 1}`,
      tool: 'postWebhook',
      args: { vertical, level: level.id, payload: chunk },
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

  try {
    for (const [index, step] of definition.steps.entries()) {
      const result = await guarded.executors[step.tool](step.args);
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
        preview: preview(result),
      });
    }

    const finalStep = steps[steps.length - 1];
    const allSignals = [...new Set(steps.flatMap((step) => step.signals))];
    const missingSignals = definition.requiredSignals.filter(
      (signal) => !allSignals.includes(signal),
    );

    return {
      vertical: definition.vertical,
      level: definition.level.id,
      name: definition.level.name,
      technique: definition.level.technique,
      mode: definition.level.mode,
      description: definition.level.description,
      trustedFile: definition.trustedFile,
      untrustedFile: definition.untrustedFile,
      passed:
        finalStep.blocked === definition.expectedBlocked && missingSignals.length === 0,
      finalBlocked: finalStep.blocked,
      expectedBlocked: definition.expectedBlocked,
      finalAction: finalStep.action,
      finalScore: finalStep.score,
      matchedSignals: allSignals.filter((signal) => definition.requiredSignals.includes(signal)),
      missingSignals,
      steps,
    };
  } finally {
    guarded.destroy();
  }
}

function summarize(results) {
  const byVertical = Object.fromEntries(
    STRESS_VERTICALS.map((vertical) => {
      const entries = results.filter((result) => result.vertical === vertical);
      return [
        vertical,
        {
          total: entries.length,
          passed: entries.filter((entry) => entry.passed).length,
          averageScore:
            entries.length === 0
              ? 0
              : entries.reduce((sum, entry) => sum + entry.finalScore, 0) / entries.length,
        },
      ];
    }),
  );

  const byLevel = Object.fromEntries(
    STRESS_LEVELS.map((level) => {
      const entries = results.filter((result) => result.level === level.id);
      return [
        level.id,
        {
          total: entries.length,
          passed: entries.filter((entry) => entry.passed).length,
        },
      ];
    }),
  );

  return {
    total: results.length,
    passed: results.filter((result) => result.passed).length,
    failed: results.filter((result) => !result.passed).length,
    byVertical,
    byLevel,
  };
}

function printResult(result) {
  const status = result.passed ? 'PASS' : 'FAIL';
  console.log(`\n[${status}] ${result.vertical} ${result.level} — ${result.name}`);
  console.log(`  blocked: expected=${result.expectedBlocked} actual=${result.finalBlocked}`);
  console.log(`  final score=${result.finalScore} action=${result.finalAction}`);
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

  if (!webhookUrl) {
    console.error('Missing required --webhook-url');
    process.exit(1);
  }

  const selectedVerticals = String(args.verticals ?? STRESS_VERTICALS.join(','))
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  const discovered = await discoverCorpus(corpusRoot, selectedVerticals);
  if (discovered.length === 0) {
    console.error(`No corpus discovered in ${corpusRoot}`);
    console.error('Expected structure: <corpus-root>/<vertical>/{trusted,untrusted}/<files>');
    process.exit(1);
  }

  const scenarios = [];
  for (const corpus of discovered) {
    const trustedText = await readFile(corpus.trustedFile, 'utf8');
    for (const level of STRESS_LEVELS) {
      const plan = buildLevelPlan(level, trustedText, corpus.vertical, webhookUrl);
      scenarios.push({
        ...corpus,
        ...plan,
        level,
        webhookUrl,
      });
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
  console.log(`  Total scenarios: ${report.summary.total}`);
  console.log(`  Passed: ${report.summary.passed}`);
  console.log(`  Failed: ${report.summary.failed}`);
  console.log(`  JSON report: ${reportJsonPath}`);

  if (report.summary.failed > 0) {
    process.exitCode = 1;
  }
}

await main();
