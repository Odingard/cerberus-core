# Verify Cerberus Core Yourself

This is the fastest way to prove Cerberus Core is doing real work, not just
showing a demo.

## 1. Install dependencies

```bash
npm install
```

## 2. Run the action harness

```bash
npm run harness:action:report
```

This runs the real `guard()` runtime against a small validation pack:

- benign control flows that should be allowed
- attack flows that should be blocked
- observation scenarios that should surface runtime signals

## 3. Open the report

- `test-results/action-harness-report.html`
- `test-results/action-harness-report.json`

What you should expect:

- benign allow rate
- prevention block rate
- observation coverage
- per-scenario steps showing:
  - which tool ran
  - whether it was blocked
  - final action
  - final score
  - matched runtime signals

## 4. Run the larger sector benchmark

Start the local sink in one terminal:

```bash
npm run validate:sink
```

In a second terminal:

```bash
npm run stress:report -- --validation-sequence local-check-01 --corpus-root ./corpus --webhook-url http://127.0.0.1:7777/capture
```

That produces:

- `test-results/stress-harness-report.html`
- `test-results/stress-harness-report.json`

## 5. Measure stability under load

```bash
npm run stress:report -- --validation-sequence local-burn-100 --repeats 100 --corpus-root ./corpus --webhook-url http://127.0.0.1:7777/capture
```

This is the same benchmark path, repeated enough to simulate sustained
enterprise-style execution.

## Notes

- The public demo is useful for first impression.
- The action harness is the fastest proof path.
- The stress harness is the deeper benchmark path.
- For the broadest credibility, use all three.
