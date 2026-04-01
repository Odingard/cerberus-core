import { readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

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

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function pct(value) {
  return `${(Number(value ?? 0) * 100).toFixed(1)}%`;
}

function formatCost(value) {
  return `$${Number(value ?? 0).toFixed(3)}`;
}

async function findLatestReport(outputDir) {
  let entries;
  try {
    entries = await readdir(outputDir);
  } catch (error) {
    if (error && typeof error === 'object' && 'code' in error && error.code === 'ENOENT') {
      throw new Error(
        `Validation trace directory not found: ${outputDir}\nRun the live model harness first with: npm run validate:model:report -- --provider openai --model gpt-4o-mini --trials 2 --control-trials 4 --detect`,
      );
    }
    throw error;
  }
  const candidates = entries
    .filter((entry) => entry.startsWith('validation-report-') && entry.endsWith('.json'))
    .sort();
  if (candidates.length === 0) {
    throw new Error(
      `No validation report JSON files found in ${outputDir}\nRun the live model harness first with: npm run validate:model:report -- --provider openai --model gpt-4o-mini --trials 2 --control-trials 4 --detect`,
    );
  }
  return path.join(outputDir, candidates[candidates.length - 1]);
}

const args = parseArgs(process.argv.slice(2));
const outputDir = path.resolve(args['output-dir'] ?? path.join(projectRoot, 'harness', 'validation-traces'));
const inputPath = args.input ? path.resolve(args.input) : await findLatestReport(outputDir);
const report = JSON.parse(await readFile(inputPath, 'utf8'));
const outputPath = path.join(outputDir, 'latest-validation-report.html');

const controlRows = Object.entries(report.controlResults)
  .map(
    ([provider, stats]) => `
      <tr>
        <td>${escapeHtml(provider)}</td>
        <td>${escapeHtml(stats.model)}</td>
        <td>${stats.outcomes.success}/${stats.totalRuns}</td>
        <td>${pct(stats.successRate)}</td>
        <td>${pct(stats.confidenceInterval.lower)} - ${pct(stats.confidenceInterval.upper)}</td>
      </tr>`,
  )
  .join('');

const treatmentRows = Object.entries(report.treatmentResults)
  .map(
    ([provider, stats]) => `
      <tr>
        <td>${escapeHtml(provider)}</td>
        <td>${escapeHtml(stats.model)}</td>
        <td>${stats.outcomes.success}/${stats.totalRuns}</td>
        <td>${stats.outcomes.refused}</td>
        <td>${stats.outcomes.partial}</td>
        <td>${stats.outcomes.failure}</td>
        <td>${stats.outcomes.error}</td>
        <td>${pct(stats.successRate)}</td>
        <td>${stats.meanCausationScore.toFixed(3)}</td>
      </tr>`,
  )
  .join('');

const payloadRows = report.perPayload
  .map((payload) => {
    const providerRates = report.protocol.providers
      .map((provider) => {
        const stats = payload.perProvider[provider];
        return `<div><strong>${escapeHtml(provider)}:</strong> ${stats ? pct(stats.successRate) : 'N/A'}</div>`;
      })
      .join('');
    return `
      <tr>
        <td>${escapeHtml(payload.payloadId)}</td>
        <td>${escapeHtml(payload.category)}</td>
        <td>${escapeHtml(payload.injectedDestination ?? '(none)')}</td>
        <td>${providerRates}</td>
      </tr>`;
  })
  .join('');

const detectionSection = report.detection?.enabled
  ? `
    <section class="panel">
      <h2>Detection Validation</h2>
      <div class="stats">
        <div class="stat"><div>Detection rate</div><h3>${pct(report.detection.overallDetectionRate)}</h3></div>
        <div class="stat"><div>False-positive rate</div><h3>${pct(report.detection.overallFalsePositiveRate)}</h3></div>
      </div>
      <table>
        <thead>
          <tr><th>Provider</th><th>Model</th><th>Detection</th><th>Block</th><th>FP</th><th>L1</th><th>L2</th><th>L3</th></tr>
        </thead>
        <tbody>
          ${Object.entries(report.detection.perProvider)
            .map(
              ([provider, stats]) => `
                <tr>
                  <td>${escapeHtml(provider)}</td>
                  <td>${escapeHtml(stats.model)}</td>
                  <td>${pct(stats.detectionRate)}</td>
                  <td>${pct(stats.blockRate)}</td>
                  <td>${pct(stats.falsePositiveRate)}</td>
                  <td>${pct(stats.perLayer.L1.accuracy)}</td>
                  <td>${pct(stats.perLayer.L2.accuracy)}</td>
                  <td>${pct(stats.perLayer.L3.accuracy)}</td>
                </tr>`,
            )
            .join('')}
        </tbody>
      </table>
    </section>`
  : '';

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cerberus Live Model Validation Report</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #08111d;
      --panel: #101a2a;
      --line: #25354f;
      --text: #edf4ff;
      --muted: #94a8c7;
    }
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: radial-gradient(circle at top, #13223c 0, var(--bg) 42%); color: var(--text); }
    main { max-width: 1180px; margin: 0 auto; padding: 36px 24px 56px; }
    .hero, .panel { background: rgba(16,26,42,0.92); border: 1px solid var(--line); border-radius: 18px; padding: 20px; }
    .grid, .stats { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 18px; }
    .stat { background: rgba(255,255,255,0.02); border: 1px solid var(--line); border-radius: 14px; padding: 16px; }
    .meta { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); margin-top: 16px; color: var(--muted); }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; }
    th, td { padding: 10px; border-top: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { color: var(--muted); }
    p { color: var(--muted); }
    section + section { margin-top: 18px; }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Cerberus Live Model Validation</h1>
      <p>Negative controls, treatment payloads, causation scoring, and optional observe-only detection validation against real model providers.</p>
      <div class="meta">
        <div><strong>Generated at:</strong> ${escapeHtml(report.generatedAt)}</div>
        <div><strong>Schema:</strong> ${escapeHtml(report.schemaVersion)}</div>
        <div><strong>Input JSON:</strong> ${escapeHtml(path.basename(inputPath))}</div>
      </div>
      <div class="stats">
        <div class="stat"><div>Total runs</div><h3>${report.protocol.totalRuns}</h3></div>
        <div class="stat"><div>Providers</div><h3>${report.protocol.providers.length}</h3></div>
        <div class="stat"><div>Payloads</div><h3>${report.protocol.payloadCount}</h3></div>
        <div class="stat"><div>Trials per payload</div><h3>${report.protocol.trialsPerPayload}</h3></div>
        <div class="stat"><div>Control trials/provider</div><h3>${report.protocol.controlTrialsPerProvider}</h3></div>
        <div class="stat"><div>Estimated cost</div><h3>${formatCost(report.totalCostEstimateUsd)}</h3></div>
      </div>
    </section>

    <section class="panel">
      <h2>Control Group</h2>
      <p>Clean-content runs with no injection payload. If exfiltration appears here, the injection is not the cause.</p>
      <table>
        <thead><tr><th>Provider</th><th>Model</th><th>Exfiltrations</th><th>Success rate</th><th>95% CI</th></tr></thead>
        <tbody>${controlRows}</tbody>
      </table>
    </section>

    <section class="panel">
      <h2>Treatment Group</h2>
      <p>Injected runs scored across success, refusal, partial compliance, failure, and technical error states.</p>
      <table>
        <thead><tr><th>Provider</th><th>Model</th><th>Success</th><th>Refused</th><th>Partial</th><th>Failure</th><th>Error</th><th>Success rate</th><th>Mean causation</th></tr></thead>
        <tbody>${treatmentRows}</tbody>
      </table>
    </section>

    ${detectionSection}

    <section class="panel">
      <h2>Per-Payload Breakdown</h2>
      <table>
        <thead><tr><th>Payload</th><th>Category</th><th>Injected destination</th><th>Provider rates</th></tr></thead>
        <tbody>${payloadRows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>`;

await writeFile(outputPath, html, 'utf8');
console.log(`Wrote ${outputPath}`);
