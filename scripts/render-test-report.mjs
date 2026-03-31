import fs from 'node:fs';
import path from 'node:path';

const root = process.cwd();
const inputPath = path.join(root, 'test-results', 'vitest-report.json');
const outputPath = path.join(root, 'test-results', 'latest-report.html');

if (!fs.existsSync(inputPath)) {
  console.error(`Missing Vitest JSON report at ${inputPath}`);
  process.exit(1);
}

const report = JSON.parse(fs.readFileSync(inputPath, 'utf8'));

const suiteRows = (report.testResults || [])
  .map((suite) => {
    const passed = suite.assertionResults.filter((test) => test.status === 'passed').length;
    const failed = suite.assertionResults.filter((test) => test.status === 'failed').length;
    const duration = Math.max(
      0,
      Math.round((suite.endTime ?? report.startTime) - (suite.startTime ?? report.startTime)),
    );
    return {
      name: suite.name.replace(`${root}/`, ''),
      passed,
      failed,
      duration,
      tests: suite.assertionResults.map((test) => ({
        title: test.fullName,
        status: test.status,
        duration: Math.round(test.duration ?? 0),
      })),
    };
  })
  .sort((a, b) => a.name.localeCompare(b.name));

const passRate =
  report.numTotalTests > 0
    ? `${((report.numPassedTests / report.numTotalTests) * 100).toFixed(1)}%`
    : '0.0%';

const criticalSuites = [
  'tests/engine/interceptor.test.ts',
  'tests/classifiers/tool-chain-detector.test.ts',
  'tests/classifiers/split-exfiltration-detector.test.ts',
  'tests/classifiers/outbound-encoding-detector.test.ts',
  'tests/layers/l3-classifier.test.ts',
];

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Cerberus Core Test Report</title>
  <style>
    :root {
      --bg: #0b0c14;
      --panel: #121522;
      --panel-2: #171a29;
      --border: #2a3045;
      --text: #e6eaf2;
      --muted: #92a0bd;
      --green: #22c55e;
      --red: #ef4444;
      --amber: #f59e0b;
      --accent: #7c3aed;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 32px;
      background: radial-gradient(circle at top, rgba(124,58,237,0.18), transparent 28%), var(--bg);
      color: var(--text);
      font: 14px/1.5 Inter, system-ui, sans-serif;
    }
    .wrap {
      max-width: 1200px;
      margin: 0 auto;
      display: grid;
      gap: 20px;
    }
    .hero, .panel {
      background: rgba(18,21,34,0.92);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 22px;
      box-shadow: 0 18px 50px rgba(0,0,0,0.28);
    }
    h1, h2, h3 { margin: 0; }
    .eyebrow {
      color: #b9a7ff;
      text-transform: uppercase;
      letter-spacing: .12em;
      font-size: 11px;
      font-weight: 700;
      margin-bottom: 10px;
    }
    .hero-grid, .stats, .critical-grid, .suite-grid {
      display: grid;
      gap: 16px;
    }
    .hero-grid { grid-template-columns: 1.5fr 1fr; }
    .stats, .critical-grid { grid-template-columns: repeat(4, minmax(0, 1fr)); }
    .suite-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .stat, .critical, .suite {
      background: var(--panel-2);
      border: 1px solid var(--border);
      border-radius: 14px;
      padding: 16px;
    }
    .value {
      font-size: 28px;
      font-weight: 800;
      margin: 4px 0;
    }
    .ok { color: var(--green); }
    .warn { color: var(--amber); }
    .fail { color: var(--red); }
    .muted { color: var(--muted); }
    .suite h3 { font-size: 15px; margin-bottom: 8px; }
    .suite-meta {
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
      color: var(--muted);
      font-size: 12px;
      margin-bottom: 10px;
    }
    ul {
      margin: 0;
      padding-left: 18px;
    }
    li + li { margin-top: 6px; }
    .pill {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      font-weight: 700;
      border: 1px solid var(--border);
      background: rgba(255,255,255,0.02);
    }
    .tests {
      margin-top: 12px;
      max-height: 240px;
      overflow: auto;
      border-top: 1px solid var(--border);
      padding-top: 12px;
    }
    .test-row {
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 6px 0;
      border-bottom: 1px solid rgba(255,255,255,0.04);
    }
    .test-row:last-child { border-bottom: none; }
    .test-title { flex: 1; color: var(--text); }
    .test-meta { color: var(--muted); white-space: nowrap; }
    @media (max-width: 980px) {
      body { padding: 18px; }
      .hero-grid, .stats, .critical-grid, .suite-grid { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <section class="hero">
      <div class="hero-grid">
        <div>
          <div class="eyebrow">Cerberus Core Verification</div>
          <h1>Visual Test Report</h1>
          <p class="muted">This report is generated from the current Vitest JSON output so you can inspect the runtime-enforcement surface without reading terminal logs.</p>
          <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:14px;">
            <span class="pill ok">Pass rate ${escapeHtml(passRate)}</span>
            <span class="pill">${escapeHtml(String(report.numPassedTests))} passed</span>
            <span class="pill ${report.numFailedTests > 0 ? 'fail' : 'ok'}">${escapeHtml(String(report.numFailedTests))} failed</span>
            <span class="pill">${escapeHtml(String(report.numPassedTestSuites))} suites green</span>
          </div>
        </div>
        <div class="panel" style="padding:16px;">
          <div class="eyebrow">Current Runtime Wedge</div>
          <div class="muted">Recently hardened:</div>
          <ul>
            <li>staged split exfiltration detection</li>
            <li>multi-hop exfiltration enforcement</li>
            <li>entity-aware outbound correlation</li>
          </ul>
        </div>
      </div>
    </section>

    <section class="stats">
      <div class="stat">
        <div class="eyebrow">Total Tests</div>
        <div class="value">${escapeHtml(String(report.numTotalTests))}</div>
        <div class="muted">Full public core package</div>
      </div>
      <div class="stat">
        <div class="eyebrow">Passed</div>
        <div class="value ok">${escapeHtml(String(report.numPassedTests))}</div>
        <div class="muted">Current run</div>
      </div>
      <div class="stat">
        <div class="eyebrow">Failed</div>
        <div class="value ${report.numFailedTests > 0 ? 'fail' : 'ok'}">${escapeHtml(String(report.numFailedTests))}</div>
        <div class="muted">Should stay at zero</div>
      </div>
      <div class="stat">
        <div class="eyebrow">Suites</div>
        <div class="value">${escapeHtml(String(report.numTotalTestSuites))}</div>
        <div class="muted">Grouped verification slices</div>
      </div>
    </section>

    <section class="panel">
      <div class="eyebrow">Critical Runtime Suites</div>
      <div class="critical-grid">
        ${criticalSuites
          .map((name) => {
            const suite = suiteRows.find((row) => row.name.endsWith(name));
            if (!suite) {
              return `<div class="critical"><h3>${escapeHtml(name)}</h3><div class="muted">Not present in this run.</div></div>`;
            }
            return `<div class="critical">
              <h3>${escapeHtml(name.replace('tests/', ''))}</h3>
              <div class="suite-meta">
                <span class="pill ok">${suite.passed} passed</span>
                <span class="pill ${suite.failed > 0 ? 'fail' : 'ok'}">${suite.failed} failed</span>
                <span class="pill">${suite.duration} ms</span>
              </div>
            </div>`;
          })
          .join('')}
      </div>
    </section>

    <section class="panel">
      <div class="eyebrow">Suite Detail</div>
      <div class="suite-grid">
        ${suiteRows
          .map(
            (suite) => `<article class="suite">
              <h3>${escapeHtml(suite.name.replace('tests/', ''))}</h3>
              <div class="suite-meta">
                <span class="pill ok">${suite.passed} passed</span>
                <span class="pill ${suite.failed > 0 ? 'fail' : 'ok'}">${suite.failed} failed</span>
                <span class="pill">${suite.duration} ms</span>
              </div>
              <div class="tests">
                ${suite.tests
                  .map(
                    (test) => `<div class="test-row">
                      <div class="test-title">${escapeHtml(test.title)}</div>
                      <div class="test-meta ${test.status === 'passed' ? 'ok' : 'fail'}">${escapeHtml(
                        test.status,
                      )} · ${test.duration} ms</div>
                    </div>`,
                  )
                  .join('')}
              </div>
            </article>`,
          )
          .join('')}
      </div>
    </section>
  </div>
</body>
</html>`;

fs.mkdirSync(path.dirname(outputPath), { recursive: true });
fs.writeFileSync(outputPath, html);
console.log(`HTML test report written to ${outputPath}`);
