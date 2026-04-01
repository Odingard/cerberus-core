# Live Model Validation

Cerberus Core includes a real provider validation harness for `OpenAI`, `Anthropic`, and `Google`.

This is different from the sector stress harness:

- the stress harness proves deterministic runtime behavior against a labeled corpus
- the live model harness measures how real models behave under clean controls and adversarial treatment payloads

## What it measures

- control-group exfiltration rate with no injection
- treatment-group success, refusal, partial, failure, and error outcomes
- causation scoring
- per-payload success rates
- optional observe-only Cerberus detection validation

## Required API keys

Set one or more of:

- `OPENAI_API_KEY`
- `ANTHROPIC_API_KEY`
- `GOOGLE_API_KEY`

You can export them in your shell or place them in a local `.env` file at the repo root.

## Fastest run

Run one provider with a small trial count first:

```bash
npm run validate:model:report -- --provider openai --model gpt-4o-mini --trials 2 --control-trials 4 --detect
```

That will:

- run the live validation protocol
- write JSON and Markdown into `harness/validation-traces/`
- render `harness/validation-traces/latest-validation-report.html`

## Full provider run

```bash
npm run validate:model:report -- --trials 5 --control-trials 10 --detect
```

## Useful filters

Single provider:

```bash
npm run validate:model:report -- --provider anthropic --trials 3 --control-trials 6 --detect
```

Specific payloads:

```bash
npm run validate:model:report -- --provider openai --payloads DI-001,SE-001 --trials 5 --control-trials 10 --detect
```

Different system prompt:

```bash
npm run validate:model:report -- --provider openai --prompt safety --trials 3 --control-trials 6 --detect
```

## Output files

- JSON: `harness/validation-traces/validation-report-*.json`
- Markdown: `harness/validation-traces/validation-report-*.md`
- HTML: `harness/validation-traces/latest-validation-report.html`

## Why this matters

This is the benchmark lane that tells you:

- how often a real model follows injected instructions
- how often it refuses
- whether Cerberus detection tracks those live outcomes in observe-only mode

Use the stress harness for deterministic runtime proof.
Use live model validation for model-behavior evidence.
