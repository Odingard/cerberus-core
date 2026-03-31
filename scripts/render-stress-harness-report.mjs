import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..');
const inputPath = path.join(projectRoot, 'test-results', 'stress-harness-report.json');
const outputPath = path.join(projectRoot, 'test-results', 'stress-harness-report.html');

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const report = JSON.parse(await readFile(inputPath, 'utf8'));

const verticalRows = Object.entries(report.summary.byVertical)
  .map(
    ([vertical, summary]) => `
      <tr>
        <td>${escapeHtml(vertical)}</td>
        <td>${summary.passed}/${summary.total}</td>
        <td>${summary.averageScore.toFixed(2)}</td>
      </tr>`,
  )
  .join('');

const levelRows = Object.entries(report.summary.byLevel)
  .map(
    ([level, summary]) => `
      <tr>
        <td>${escapeHtml(level)}</td>
        <td>${summary.passed}/${summary.total}</td>
      </tr>`,
  )
  .join('');

const scenarios = report.results
  .map(
    (result) => `
      <section class="scenario">
        <div class="top">
          <div>
            <div class="eyebrow">${escapeHtml(result.vertical)} · ${escapeHtml(result.level)} · ${escapeHtml(result.technique)}</div>
            <h2>${escapeHtml(result.name)}</h2>
            <p>${escapeHtml(result.description)}</p>
          </div>
          <div class="pill ${result.passed ? 'pass' : 'fail'}">${result.passed ? 'PASS' : 'FAIL'}</div>
        </div>
        <div class="meta">
          <div><strong>Blocked:</strong> expected ${result.expectedBlocked} · actual ${result.finalBlocked}</div>
          <div><strong>Final action:</strong> ${escapeHtml(result.finalAction)}</div>
          <div><strong>Final score:</strong> ${result.finalScore}</div>
          <div><strong>Matched signals:</strong> ${escapeHtml(result.matchedSignals.join(', ') || 'none')}</div>
          <div><strong>Missing signals:</strong> ${escapeHtml(result.missingSignals.join(', ') || 'none')}</div>
        </div>
      </section>`,
  )
  .join('\n');

const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Cerberus Stress Harness Report</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #08111d;
      --panel: #101a2a;
      --line: #25354f;
      --text: #edf4ff;
      --muted: #94a8c7;
      --good: #19c37d;
      --bad: #ff5d73;
    }
    body { margin: 0; font-family: ui-sans-serif, system-ui, sans-serif; background: radial-gradient(circle at top, #13223c 0, var(--bg) 42%); color: var(--text); }
    main { max-width: 1180px; margin: 0 auto; padding: 36px 24px 56px; }
    .hero, .panel, .scenario { background: rgba(16,26,42,0.92); border: 1px solid var(--line); border-radius: 18px; padding: 20px; }
    .grid { display: grid; gap: 18px; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); margin-top: 18px; }
    .scenario-list { display: grid; gap: 16px; margin-top: 22px; }
    .top { display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; }
    .eyebrow { color: #f5b94a; text-transform: uppercase; letter-spacing: 0.08em; font-size: 12px; margin-bottom: 8px; }
    p { color: var(--muted); }
    .pill { border-radius: 999px; padding: 8px 12px; font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; border: 1px solid var(--line); }
    .pill.pass { color: var(--good); }
    .pill.fail { color: var(--bad); }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; border-top: 1px solid var(--line); text-align: left; }
    th { color: var(--muted); }
    .meta { display: grid; gap: 10px; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); margin-top: 16px; color: var(--muted); }
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Cerberus Stress Harness</h1>
      <p>Sector + difficulty benchmark using real corpora and real guarded outbound actions. This report shows how Cerberus performs across Enterprise, SMB, Supply Chain, and Medical stress scenarios.</p>
      <div class="grid">
        <div class="panel"><div>Total scenarios</div><h2>${report.summary.total}</h2></div>
        <div class="panel"><div>Passed</div><h2>${report.summary.passed}</h2></div>
        <div class="panel"><div>Failed</div><h2>${report.summary.failed}</h2></div>
      </div>
    </section>
    <section class="grid">
      <section class="panel">
        <h2>By Vertical</h2>
        <table>
          <thead><tr><th>Vertical</th><th>Pass Rate</th><th>Avg Score</th></tr></thead>
          <tbody>${verticalRows}</tbody>
        </table>
      </section>
      <section class="panel">
        <h2>By Difficulty Level</h2>
        <table>
          <thead><tr><th>Level</th><th>Pass Rate</th></tr></thead>
          <tbody>${levelRows}</tbody>
        </table>
      </section>
    </section>
    <section class="scenario-list">${scenarios}</section>
  </main>
</body>
</html>`;

await mkdir(path.dirname(outputPath), { recursive: true });
await writeFile(outputPath, html, 'utf8');
console.log(`Wrote ${outputPath}`);
