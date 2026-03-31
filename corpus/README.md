# Cerberus Corpus

This directory ships with a structured synthetic starter corpus so the stress harness can run out of the box.

For stronger validation, Cerberus stress testing should eventually run against:

- real internal documents you are authorized to use
- or redacted-real documents that preserve authentic structure and attack surface

Do not treat the starter corpus as the final benchmark. Replace or extend it with redacted-real data when possible.

## Required structure

```text
corpus/
  enterprise/
    trusted/
      manifest.json
      <one or more real trusted files>
    untrusted/
      manifest.json
      <one or more real attacker-controlled or hostile-content files>
  smb/
    trusted/
      manifest.json
      ...
    untrusted/
      manifest.json
      ...
  supply-chain/
    trusted/
      manifest.json
      ...
    untrusted/
      manifest.json
      ...
  medical/
    trusted/
      manifest.json
      ...
    untrusted/
      manifest.json
      ...
```

## Manifest format

Each `trusted/manifest.json` and `untrusted/manifest.json` should look like:

```json
{
  "vertical": "medical",
  "lane": "trusted",
  "documents": [
    {
      "path": "patient-export-q1.txt",
      "label": "Patient export Q1",
      "source": "redacted production export",
      "sensitivity": "phi",
      "notes": "Contains real workflow structure with redacted identifiers"
    }
  ]
}
```

For `untrusted` manifests, use `sensitivity: "hostile"` and describe where the hostile content came from.

## Workflow

1. Scaffold directories:

```bash
npm run corpus:init
```

2. Add your real or redacted-real files and manifests.

3. Validate the corpus:

```bash
npm run corpus:check
```

4. Run the stress harness:

```bash
npm run stress:report -- --corpus-root /absolute/path/to/corpus --webhook-url http://127.0.0.1:7777/capture
```
