# DSA-PEAS Record Schema — v0.2

**DSA-PEAS** — *Dependency-Signed, Authorship-Provable Evidence of Storage* — is
the public wire format for a single memory-provenance record as emitted by the
Cerberus provenance ledger (`src/graph/ledger.ts`, `src/graph/authorship.ts`).
This document pins the spec's v0.2 wire format to what the reference
implementation actually emits: field names, types, serialization, and the exact
byte derivations a conformant verifier must reproduce.

It is paired with a **standalone conformance validator**
(`spec/dsa-peas/validator.ts` + `cli.ts`) that depends on nothing but Node's
built-in `node:crypto` — no Cerberus internals, no database, no third-party
packages. Anyone can verify a record (or a stream) against this schema without
the reference implementation.

---

## 1. Assurance levels

A record carries one of two assurance levels. Higher levels are strictly
additive — an AL3 record is also a valid AL2 record.

| Level | Name | Guarantee | Mechanism |
|-------|------|-----------|-----------|
| **AL2** | tamper-**evident** | Detects post-hoc edits to a record's content or declared dependencies. Proves the record is *untampered*. | `commitment` = SHA-256 over content + deps. |
| **AL3** | authorship-**provable** | Additionally proves *who* wrote the record. A forged or altered author is detectable. | Per-author Ed25519 `signature` over the commitment, bound to the author. |

AL2 alone is *evidence*, not *authentication*: anyone who can recompute the
commitment hash can mint a valid-looking one. AL3 closes that gap by binding the
commitment to an author keypair.

---

## 2. Record schema

A record is a JSON object. Field names are camelCase; this is the canonical
serialization (the SQLite column names in the reference store are an internal
detail — the wire form is this JSON shape).

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `nodeId` | `string` | yes | Identity of the memory cell written. |
| `sessionId` | `string` | yes | Session the write occurred in. |
| `trustLevel` | `"trusted" \| "untrusted" \| "unknown"` | yes | Trust classification of the write's source. |
| `source` | `string` | yes | Origin of the write (sensor, tool, agent id, …). |
| `contentHash` | `string` (lowercase hex, 64 chars) | yes | SHA-256 of the written content. |
| `timestamp` | `number` (integer, ms since epoch) | yes | When the write was recorded. |
| `deps` | `string[]` | yes | Observed-read dependency `nodeId`s — a **conservative over-approximation** of true data dependencies. May be empty (a root). |
| `commitment` | `string` (lowercase hex, 64 chars) | yes | Tamper-evident commitment binding `contentHash` + `deps` (see §3). |
| `author` | `string` | AL3 only | Claimed author/writer. Absent (or empty) ⇒ unsigned (AL2). |
| `signature` | `string` (base64) | AL3 only | Ed25519 signature over (`commitment` ‖ `author`) (see §4). Absent ⇒ unsigned. |

`deps` is deliberately an over-approximation: the framework cannot know which
reads actually informed a write, so it records every observed read. This is what
makes the forward-reachable **blast radius** B(p) a conservative *superset* of
true contamination (§5) — the safe direction for a containment tool.

---

## 3. AL2 — the commitment (canonical bytes)

```
canonicalDeps = unique(deps) sorted lexicographically (UTF-16 code-unit order)
preimage      = contentHash ‖ "\n" ‖ canonicalDeps.join("\n")
commitment    = lowercase_hex( SHA-256( utf8(preimage) ) )
```

Properties a conformant verifier MUST reproduce:

- **Dedup + sort**: `deps` are de-duplicated and sorted before hashing, so the
  commitment is invariant to dep ordering and duplication.
- **Binding**: mutating `contentHash` *or* any dependency changes the preimage
  and therefore the commitment. A verifier recomputes the commitment from
  `contentHash` + `deps` and compares to the stored field — a mismatch means the
  record was altered.

---

## 4. AL3 — the authorship signature (canonical bytes)

```
signedBytes = "dsa-peas-al3-v1" ‖ "\n" ‖ commitment ‖ "\n" ‖ author     (UTF-8)
signature   = base64( Ed25519_sign( authorPrivateKey, signedBytes ) )
```

Verification, given the record and a keyring (author → SPKI PEM public key):

1. Re-derive the `commitment` from `contentHash` + `deps` (**not** the stored
   field) — so altered content or deps also break the signature.
2. Build `signedBytes` using the record's **claimed** `author`.
3. Verify the base64 `signature` with the claimed author's registered public
   key.

This rejects, in one check:

- **altered content / altered deps** — the re-derived commitment differs;
- **altered author** — the author is mixed into `signedBytes`;
- **forged author** — verifying against the *claimed* author's key means a
  signature minted by any other key fails;
- **unknown author** — no registered key ⇒ fail.

The `"dsa-peas-al3-v1"` domain-separation prefix (vendor-neutral) ensures an authorship signature
can never be replayed as a signature over some other protocol's bytes. Private
keys never appear in a record or a keyring — only public SPKI PEM keys are
shared.

---

## 5. Blast radius (AL2 superset / no false negatives)

From a stream of records, the **blast radius** B(p) of a record `p` is the set
of all records transitively reachable from `p` over the dependency edges
(`dep → dependent`). Because `deps` is a conservative over-approximation, B(p)
is a **superset** of the true descendant set: it may contain extra nodes
(over-containment — safe), but it can **never miss** a true descendant (a false
negative would let poison escape).

A conformant verifier MUST be able to compute B(p) from a record stream and
confirm the **no-false-negative** property: every node's blast radius is *closed
under descendants* — if a record is contained, every record depending on it is
contained too. The validator checks this across the whole stream.

---

## 6. Example records

See [`examples/records.json`](./examples/records.json) (a 4-record DAG mixing AL2
and AL3) and [`examples/keyring.json`](./examples/keyring.json) (public keys
only). They are committed conformance fixtures — run them through the validator
with `npm run dsa-peas:validate -- spec/dsa-peas/examples/records.json --keyring
spec/dsa-peas/examples/keyring.json` to confirm they pass against this spec.

**AL2 record (a root — no deps, unsigned):**

```json
{
  "nodeId": "mem:root-doc",
  "sessionId": "session:dsa-peas-demo",
  "trustLevel": "trusted",
  "source": "sensor:document-ingest",
  "contentHash": "391b0502ccee2a8b630f869f611cde96f1d314695a0b8ea1b28cfc29c3b88727",
  "timestamp": 1700000000000,
  "deps": [],
  "commitment": "af4ad7844be4306ebe136aa2887b762bb96375bbe1e65da162e1a5f1e7f0394c"
}
```

**AL3 record (signed, with deps):**

```json
{
  "nodeId": "mem:plan",
  "sessionId": "session:dsa-peas-demo",
  "trustLevel": "trusted",
  "source": "agent:planner",
  "contentHash": "7d57a8dab570134256a4fbd61a8cf9df135e90ed98f77b817fa97eb77fdcd844",
  "timestamp": 1700000002000,
  "deps": ["mem:root-doc", "mem:summary"],
  "commitment": "0411e94e091b4d467d4e9f1dc6a34e05769c977c253179afddc5e9311efea47f",
  "author": "agent:planner",
  "signature": "<base64 Ed25519 signature>"
}
```

> The `signature` and the keyring's public keys are a matched pair regenerated
> together; the example values above are illustrative. The exact committed
> signature lives in `examples/records.json`.

---

## 7. Conformance validator

```bash
# Validate the committed examples
npm run dsa-peas:validate -- spec/dsa-peas/examples/records.json \
  --keyring spec/dsa-peas/examples/keyring.json

# Validate your own records (file, or '-' for stdin); add --json for machine output
npm run dsa-peas:validate -- my-records.jsonl --keyring my-keyring.json
```

The validator reports, per record: AL2 (commitment verifies + content/deps
mutation rejected) and AL3 (signature verifies + altered/forged author
rejected); and per stream: the blast-radius superset property. It exits non-zero
if any applicable check fails. The implementation
([`validator.ts`](./validator.ts)) imports only `node:crypto`, so it can be
lifted out of this repo and dropped into any toolchain to self-check
conformance.
