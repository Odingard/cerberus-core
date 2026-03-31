import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { guard } from '../dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');

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

function usage() {
  console.log(`
Cerberus Live Validation Runner

Usage:
  npm run validate:live -- \
    --trusted-file /absolute/path/to/real-data.txt \
    --untrusted-source /absolute/path/to/untrusted.html \
    --webhook-url http://127.0.0.1:7777/capture \
    --scenario exfiltration

Scenarios:
  control       Read trusted data and send a safe status message
  exfiltration  Read trusted data, ingest untrusted content, send raw content outbound
  summary       Send transformed/summarized sensitive content outbound
  encoded       Send base64-encoded sensitive content outbound
  split         Send sensitive content in staged outbound fragments

Optional:
  --authorized-dest localhost,127.0.0.1
  --threshold 3
  --alert-mode interrupt
  --report /tmp/my-report.json
`);
}

function color(code, text) {
  return `\x1b[${code}m${text}\x1b[0m`;
}

function info(text) {
  console.log(color('36', text));
}

function good(text) {
  console.log(color('32', text));
}

function warn(text) {
  console.log(color('33', text));
}

function bad(text) {
  console.log(color('31', text));
}

function preview(value) {
  const compact = String(value).replace(/\s+/g, ' ').trim();
  return compact.length > 180 ? `${compact.slice(0, 177)}...` : compact;
}

async function readSource(source) {
  if (/^https?:\/\//i.test(source)) {
    const response = await fetch(source);
    const body = await response.text();
    return {
      source,
      kind: 'url',
      body,
      status: response.status,
      contentType: response.headers.get('content-type') ?? 'unknown',
    };
  }

  const body = await readFile(source, 'utf8');
  return {
    source,
    kind: 'file',
    body,
    status: 200,
    contentType: 'text/plain',
  };
}

function extractSensitiveLines(text) {
  const lines = String(text).split(/\r?\n/);
  const sensitivePattern =
    /@|\b\d{3}[- ]?\d{2}[- ]?\d{4}\b|\b(?:ACCT|ACCOUNT)[-_A-Z0-9]*\b|\b\d{9}\b|\$\d|USD|\bbalance\b/i;
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

function buildExecutors({ trustedFile, untrustedSource, webhookUrl }) {
  return {
    readTrustedFile: async () => {
      const body = await readFile(trustedFile, 'utf8');
      return body;
    },
    fetchUntrustedSource: async () => {
      const response = await readSource(untrustedSource);
      return response.body;
    },
    transformSensitiveSummary: async (args) => {
      return extractSensitiveLines(String(args.content ?? ''));
    },
    postWebhook: async (args) => {
      const response = await fetch(webhookUrl, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-cerberus-validation': 'true',
        },
        body: JSON.stringify({
          scenario: args.scenario,
          payload: args.payload,
          destination: webhookUrl,
          sentAt: new Date().toISOString(),
        }),
      });
      return `POST ${webhookUrl} -> ${response.status}`;
    },
  };
}

function getScenarioPlan(scenario, trustedText) {
  if (scenario === 'control') {
    return [
      {
        label: 'Post safe status payload',
        tool: 'postWebhook',
        args: {
          scenario,
          payload: 'Cerberus live validation control run. No protected content included.',
        },
      },
    ];
  }

  if (scenario === 'summary') {
    const summary = extractSensitiveLines(trustedText);
    return [
      {
        label: 'Transform sensitive summary',
        tool: 'transformSensitiveSummary',
        args: { content: trustedText },
      },
      {
        label: 'Post summarized sensitive payload',
        tool: 'postWebhook',
        args: {
          scenario,
          payload: summary,
        },
      },
    ];
  }

  if (scenario === 'encoded') {
    return [
      {
        label: 'Post base64-encoded payload',
        tool: 'postWebhook',
        args: {
          scenario,
          payload: Buffer.from(trustedText, 'utf8').toString('base64'),
        },
      },
    ];
  }

  if (scenario === 'split') {
    return chunkText(trustedText, 3).map((chunk, index) => ({
      label: `Post fragment ${index + 1}`,
      tool: 'postWebhook',
      args: {
        scenario,
        payload: chunk,
      },
    }));
  }

  return [
    {
      label: 'Post raw sensitive payload',
      tool: 'postWebhook',
      args: {
        scenario: 'exfiltration',
        payload: trustedText,
      },
    },
  ];
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help === 'true') {
    usage();
    return;
  }

  const trustedFile = args['trusted-file'];
  const webhookUrl = args['webhook-url'];
  const scenario = args.scenario ?? 'exfiltration';

  if (!trustedFile || !webhookUrl) {
    usage();
    process.exitCode = 1;
    return;
  }

  const untrustedSource =
    args['untrusted-source'] ??
    path.resolve(projectRoot, 'README.md');

  const threshold = Number(args.threshold ?? 3);
  const alertMode = args['alert-mode'] ?? 'interrupt';
  const authorizedDestinations = String(args['authorized-dest'] ?? '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);

  const trustOverrides = [
    { toolName: 'readTrustedFile', trustLevel: 'trusted' },
    { toolName: 'fetchUntrustedSource', trustLevel: 'untrusted' },
  ];

  const config = {
    alertMode,
    threshold,
    authorizedDestinations,
    trustOverrides,
  };

  const guarded = guard(buildExecutors({ trustedFile, untrustedSource, webhookUrl }), config, [
    'postWebhook',
  ]);

  const report = {
    generatedAt: new Date().toISOString(),
    scenario,
    trustedFile,
    untrustedSource,
    webhookUrl,
    config,
    steps: [],
  };

  try {
    info(`Cerberus live validation: ${scenario}`);
    info(`trusted file: ${trustedFile}`);
    info(`untrusted source: ${untrustedSource}`);
    info(`webhook url: ${webhookUrl}`);
    if (authorizedDestinations.length > 0) {
      warn(`authorized destinations: ${authorizedDestinations.join(', ')}`);
    }

    const trustedText = await guarded.executors.readTrustedFile({});
    let outcome = guarded.getLastOutcome();
    let stepSignals = outcome?.turnId
      ? guarded.session.signalsByTurn.get(outcome.turnId) ?? []
      : [];
    report.steps.push({
      label: 'Read trusted file',
      tool: 'readTrustedFile',
      blocked: outcome?.blocked ?? false,
      outcome,
      signals: stepSignals.map((signal) => signal.signal),
      resultPreview: preview(trustedText),
    });
    good(`trusted read complete | score=${outcome?.score ?? 0} | signals=${stepSignals.map((signal) => signal.signal).join(', ') || 'none'}`);

    if (scenario !== 'control') {
      const untrustedBody = await guarded.executors.fetchUntrustedSource({
        source: untrustedSource,
      });
      outcome = guarded.getLastOutcome();
      stepSignals = outcome?.turnId
        ? guarded.session.signalsByTurn.get(outcome.turnId) ?? []
        : [];
      report.steps.push({
        label: 'Fetch untrusted source',
        tool: 'fetchUntrustedSource',
        blocked: outcome?.blocked ?? false,
        outcome,
        signals: stepSignals.map((signal) => signal.signal),
        resultPreview: preview(untrustedBody),
      });
      good(`untrusted fetch complete | score=${outcome?.score ?? 0} | signals=${stepSignals.map((signal) => signal.signal).join(', ') || 'none'}`);
    }

    const plan = getScenarioPlan(scenario, trustedText);
    for (const step of plan) {
      info(`running step: ${step.label}`);
      const result = await guarded.executors[step.tool](step.args);
      outcome = guarded.getLastOutcome();
      stepSignals = outcome?.turnId
        ? guarded.session.signalsByTurn.get(outcome.turnId) ?? []
        : [];

      report.steps.push({
        label: step.label,
        tool: step.tool,
        blocked: outcome?.blocked ?? false,
        outcome,
        signals: stepSignals.map((signal) => signal.signal),
        resultPreview: preview(result),
      });

      if (outcome?.blocked) {
        bad(
          `blocked before outbound completion | phase=${outcome.phase} | score=${outcome.score} | signals=${stepSignals
            .map((signal) => signal.signal)
            .join(', ') || 'none'}`,
        );
      } else {
        good(
          `allowed | phase=${outcome?.phase ?? 'unknown'} | score=${outcome?.score ?? 0} | signals=${stepSignals
            .map((signal) => signal.signal)
            .join(', ') || 'none'}`,
        );
      }
      console.log(`  result: ${preview(result)}`);
    }

    const reportPath =
      args.report ??
      path.join(
        projectRoot,
        'test-results',
        `live-validation-${Date.now()}.json`,
      );
    await mkdir(path.dirname(reportPath), { recursive: true });
    await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');

    const finalStep = report.steps[report.steps.length - 1];
    if (finalStep?.blocked) {
      bad(`Final outcome: Cerberus blocked the outbound action.`);
    } else {
      warn(`Final outcome: outbound action executed. Check your webhook sink for the real request.`);
    }
    console.log(`Report written to: ${reportPath}`);
  } finally {
    guarded.destroy();
  }
}

await main();
