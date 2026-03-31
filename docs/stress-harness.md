# Cerberus Stress Harness

Cerberus now supports a sector-and-difficulty stress harness that runs the real `guard()` runtime against real corpora you provide.

## Goal

Produce a benchmark that speaks in customer terms:

- benign allow rate
- attack block rate
- signal coverage
- sector coverage
- difficulty coverage

## Corpus structure

Create a corpus root like this:

```text
corpus/
  enterprise/
    trusted/
      customer-data.txt
    untrusted/
      attacker-guidelines.html
  smb/
    trusted/
      invoices.txt
    untrusted/
      attacker-note.txt
  supply-chain/
    trusted/
      vendor-ledger.txt
    untrusted/
      procurement-update.html
  medical/
    trusted/
      patient-records.txt
    untrusted/
      billing-directive.html
  legal/
    trusted/
      matter-ledger.txt
    untrusted/
      portal-note.html
  insurance/
    trusted/
      claims-ledger.txt
    untrusted/
      adjuster-update.txt
```

Only real or redacted-real corpora should go here. The harness is designed to avoid demo fixtures and run against actual files you choose.

Bootstrap the structure with:

```bash
npm run corpus:init
```

Each `trusted/` and `untrusted/` lane should also contain a `manifest.json` that points to the actual files used in the benchmark.

## Run

Start a local sink:

```bash
npm run validate:sink
```

Then run the stress harness:

```bash
npm run stress:report -- --corpus-root /absolute/path/to/corpus --webhook-url http://127.0.0.1:7777/capture
```

## Difficulty ladder

- `L1` Authorized control
- `L2` Direct raw exfiltration
- `L3` Encoded exfiltration
- `L4` Transformed summary exfiltration
- `L5` Staged fragment reassembly
- `L6` Hostile domain clustering
- `L7` Sequential chunk export

## Output

- JSON: `test-results/stress-harness-report.json`
- HTML: `test-results/stress-harness-report.html`

The HTML report is meant to be operator-legible for customer briefings and analyst reviews.
