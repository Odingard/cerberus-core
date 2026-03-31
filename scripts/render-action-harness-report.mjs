import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const inputPath = path.join(projectRoot, 'test-results', 'action-harness-report.json');
const outputPath = path.join(projectRoot, 'test-results', 'action-harness-report.html');

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function badgeClass(kind) {
  if (kind === 'control') return 'control';
  if (kind === 'attack') return 'attack';
  return 'observation';
}

const raw = await readFile(inputPath, 'utf8');
const report = JSON.parse(raw);

const cards = report.results
  .map((result) => {
    const steps = result.steps
      .map(
        (step) => `
          <tr>
            <td>${step.index + 1}</td>
            <td><code>${escapeHtml(step.tool)}</code></td>
            <td>${escapeHtml(step.action)}</td>
            <td>${step.score}</td>
            <td>${step.blocked ? 'blocked' : 'allowed'}</td>
            <td>${escapeHtml(step.signals.join(', ') || 'none')}</td>
          </tr>`,
      )
      .join('');

    return `
      <section class="scenario">
        <div class="scenario-head">
          <div>
            <div class="kicker">${escapeHtml(result.id)}</div>
            <h2>${escapeHtml(result.name)}</h2>
            <p>${escapeHtml(result.description)}</p>
          </div>
          <div class="pill ${badgeClass(result.kind)}">${escapeHtml(result.kind)}</div>
        </div>
        <div class="meta">
          <div><strong>Status:</strong> ${result.passed ? 'PASS' : 'FAIL'}</div>
          <div><strong>Expected blocked:</strong> ${result.expectedBlocked}</div>
          <div><strong>Actual blocked:</strong> ${result.finalBlocked}</div>
          <div><strong>Final score:</strong> ${result.finalScore}</div>
          <div><strong>Final action:</strong> ${escapeHtml(result.finalAction)}</div>
          <div><strong>Matched signals:</strong> ${escapeHtml(result.matchedSignals.join(', ') || 'none')}</div>
          <div><strong>Missing signals:</strong> ${escapeHtml(result.missingSignals.join(', ') || 'none')}</div>
        </div>
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Tool</th>
              <th>Action</th>
              <th>Score</th>
              <th>Outcome</th>
              <th>Signals</th>
            </tr>
          </thead>
          <tbody>${steps}</tbody>
        </table>
      </section>`;
  })
  .join('\n');

const html = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Cerberus Action Harness Report</title>
    <style>
      :root {
        color-scheme: dark;
        --bg: #0a0f18;
        --panel: #101827;
        --panel-2: #172235;
        --text: #ecf3ff;
        --muted: #97a9c4;
        --green: #19c37d;
        --red: #ff5d73;
        --amber: #f3b54a;
        --line: #26344a;
      }
      body {
        margin: 0;
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        background: radial-gradient(circle at top, #12213a 0, var(--bg) 45%);
        color: var(--text);
      }
      main {
        max-width: 1180px;
        margin: 0 auto;
        padding: 40px 24px 64px;
      }
      h1, h2, p { margin: 0; }
      .hero {
        padding: 28px;
        border: 1px solid var(--line);
        background: linear-gradient(180deg, rgba(16,24,39,0.95), rgba(10,15,24,0.95));
        border-radius: 20px;
        box-shadow: 0 18px 60px rgba(0,0,0,0.28);
      }
      .hero p { color: var(--muted); margin-top: 10px; max-width: 760px; line-height: 1.5; }
      .summary {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 16px;
        margin-top: 24px;
      }
      .metric {
        background: rgba(16,24,39,0.88);
        border: 1px solid var(--line);
        border-radius: 16px;
        padding: 18px;
      }
      .metric .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; }
      .metric .value { margin-top: 8px; font-size: 28px; font-weight: 700; }
      .scenarios { display: grid; gap: 18px; margin-top: 26px; }
      .scenario {
        background: rgba(16,24,39,0.9);
        border: 1px solid var(--line);
        border-radius: 18px;
        padding: 20px;
      }
      .scenario-head {
        display: flex;
        justify-content: space-between;
        gap: 20px;
        align-items: flex-start;
      }
      .scenario-head p { margin-top: 8px; color: var(--muted); line-height: 1.5; max-width: 780px; }
      .kicker {
        color: var(--amber);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.1em;
        margin-bottom: 8px;
      }
      .pill {
        border-radius: 999px;
        padding: 7px 12px;
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.08em;
        border: 1px solid var(--line);
      }
      .pill.control { color: var(--green); }
      .pill.attack { color: var(--red); }
      .pill.observation { color: var(--amber); }
      .meta {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 12px;
        margin: 18px 0;
        color: var(--muted);
      }
      table {
        width: 100%;
        border-collapse: collapse;
        overflow: hidden;
        border-radius: 12px;
      }
      th, td {
        border-top: 1px solid var(--line);
        padding: 12px 10px;
        text-align: left;
        vertical-align: top;
        font-size: 14px;
      }
      th { color: var(--muted); font-weight: 600; }
      code {
        font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
        background: rgba(255,255,255,0.05);
        padding: 2px 6px;
        border-radius: 6px;
      }
    </style>
  </head>
  <body>
    <main>
      <section class="hero">
        <h1>Cerberus Action Harness Report</h1>
        <p>
          Real <code>guard()</code> scenarios executed against the public Core runtime. This report
          shows whether Cerberus allowed benign flows, interrupted attack flows, and surfaced the
          expected runtime signals for staged and transformed exfiltration paths.
        </p>
        <div class="summary">
          <div class="metric"><div class="label">Generated</div><div class="value">${escapeHtml(report.generatedAt)}</div></div>
          <div class="metric"><div class="label">Passed</div><div class="value">${report.summary.passed}/${report.summary.total}</div></div>
          <div class="metric"><div class="label">Benign Allow Rate</div><div class="value">${report.summary.benignPassed}/${report.summary.benignTotal}</div></div>
          <div class="metric"><div class="label">Attack Block Rate</div><div class="value">${report.summary.preventionPassed}/${report.summary.preventionTotal}</div></div>
          <div class="metric"><div class="label">Observation Coverage</div><div class="value">${report.summary.observationPassed}/${report.summary.observationTotal}</div></div>
          <div class="metric"><div class="label">Avg Final Score</div><div class="value">${report.summary.averageFinalScore.toFixed(2)}</div></div>
        </div>
      </section>
      <section class="scenarios">${cards}</section>
    </main>
  </body>
</html>`;

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, html, 'utf8');
console.log(`Wrote ${outputPath}`);
