<div align="center">

<img src="assets/cerberus-banner.svg" alt="Cerberus — Agentic AI Runtime Security" width="100%" />

# Cerberus Core

**Runtime Security For AI Agent Tool Execution**

[![npm version](https://img.shields.io/npm/v/@cerberus-ai/core.svg)](https://www.npmjs.com/package/@cerberus-ai/core)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![npm downloads](https://img.shields.io/npm/dm/@cerberus-ai/core.svg)](https://www.npmjs.com/package/@cerberus-ai/core)
[![PyPI version](https://img.shields.io/pypi/v/cerberus-ai.svg)](https://pypi.org/project/cerberus-ai/)

Embeddable runtime detection for AI agents. Cerberus correlates privileged data access, untrusted content ingestion, and outbound behavior at the tool-call level, then interrupts guarded outbound actions before they execute.

[**Product**](https://cerberus.sixsenseenterprise.com) · [**npm**](https://www.npmjs.com/package/@cerberus-ai/core) · [**PyPI**](https://pypi.org/project/cerberus-ai/) · [**Enterprise**](mailto:enterprise@sixsenseenterprise.com)

</div>

---

> [!NOTE]
> This repository is the **open core** of Cerberus — the MIT-licensed detection engine, framework adapters, and type contracts published as [`@cerberus-ai/core`](https://www.npmjs.com/package/@cerberus-ai/core) (npm) and [`cerberus-ai`](https://pypi.org/project/cerberus-ai/) (PyPI). The licensed **Enterprise** edition adds a self-hosted gateway, durable provenance ledger, blast-radius containment, and production deployment tooling — see [cerberus.sixsenseenterprise.com](https://cerberus.sixsenseenterprise.com).

---

## What is Cerberus?

Every AI agent that can **(1) access private data, (2) read external content, and (3) send data outbound** is exploitable via prompt injection — using free API access and three tool calls. This is the **Lethal Trifecta**.

```
1. PRIVILEGED ACCESS   — Agent reads customer records, credentials, internal docs
2. INJECTION           — Attacker embeds instructions in a web page the agent fetches
3. EXFILTRATION        — Agent follows the injected instruction and sends data outbound
```

Cerberus closes this gap by monitoring every tool call in real time, correlating signals across the session, and blocking the attack before a single byte leaves your system.

```bash
npm install @cerberus-ai/core
# or
pip install cerberus-ai
```

```typescript
const { executors: tools } = guard(rawTools, config, ['sendEmail']);
// Two lines. Attack intercepted.
```

> [!IMPORTANT]
> Cerberus operates at the **tool-call level** — not the prompt level. It does not read or modify LLM prompts. It watches what tools the agent *calls* and what data flows through them, making it robust to prompt variations and model updates.

<div align="center">
<img src="assets/demo.gif" alt="Cerberus terminal demo — attack blocked in real-time" width="90%" />
</div>

Run it yourself — no API key required (simulated tool executors, full detection pipeline):

```bash
npx tsx examples/demo-capture.ts
```

---

## Open Core vs Enterprise

The detection engine is identical in both tiers. The Enterprise tier adds durability, containment at scale, attested authorship, and zero-code deployment.

| | **Core (this repo, MIT)** | **Enterprise (licensed)** |
|--|---------------------------|---------------------------|
| **Detection pipeline (L1–L4)** | ✓ | ✓ |
| **10 sub-classifiers + correlation engine** | ✓ | ✓ |
| **`guard()` / `inspect()` developer API** | ✓ | ✓ |
| **Framework adapters** (LangChain, Vercel AI, OpenAI Agents) | ✓ | ✓ |
| **Signed-manifest delegation gate** (Ed25519 / KMS) | ✓ | ✓ |
| **In-memory provenance ledger** | ✓ | ✓ |
| **Durable provenance ledger + blast-radius `B(p)` containment** | — | ✓ |
| **Per-agent authorship signatures (AL3)** | — | ✓ |
| **Zero-code HTTP gateway / sidecar proxy** | — | ✓ |
| **OpenTelemetry recorder + Grafana stack** | — | ✓ |
| **Tamper-evident audit log, license/metering** | — | ✓ |
| **Support** | Community | Commercial, annual license |

Enterprise: [**cerberus.sixsenseenterprise.com**](https://cerberus.sixsenseenterprise.com) · [enterprise@sixsenseenterprise.com](mailto:enterprise@sixsenseenterprise.com)

---

## What It Detects

Cerberus runs a **4-layer detection pipeline** with **10 sub-classifiers** sharing one correlation engine.

### Core Detection Layers

| Layer | Name | Signal | What It Catches |
|-------|------|--------|-----------------|
| **L1** | Data Source Classifier | `PRIVILEGED_DATA_ACCESSED` | Privileged data (PII, secrets, credentials) entered the agent context |
| **L2** | Token Provenance Tagger | `UNTRUSTED_TOKENS_IN_CONTEXT` | External content (web, API, email) is in context before an outbound call |
| **L3** | Outbound Intent Classifier | `EXFILTRATION_RISK` | Agent is sending data that matches privileged content to an external destination |
| **L4** | Memory Contamination Graph | `CONTAMINATED_MEMORY_ACTIVE` | Injected instructions persisted across conversation turns (cross-session attack) |

### Sub-Classifiers

Ten heuristic layers sit inside the pipeline, sharpening L1–L3 without adding to the risk score:

| Sub-Classifier | Enhances | What It Catches |
|----------------|----------|-----------------|
| **Secrets Detector** | L1 | AWS keys, GitHub tokens, JWTs, private keys, connection strings |
| **Injection Scanner** | L2 | Role overrides, authority spoofing, exfiltration commands, instruction injection |
| **Encoding Detector** | L2 | Base64, hex, unicode, URL encoding, HTML entities, ROT13 hiding payloads |
| **MCP Poisoning Scanner** | L2 | Hidden instructions embedded in tool *descriptions* (not just results) |
| **Domain Classifier** | L3 | Free-tier webhooks, disposable email providers, social-engineering domains |
| **Outbound Correlator** | L3 | Injection-to-exfiltration chain even when PII is summarized or transformed |
| **Tool Chain Detector** | L3 | Multi-hop exfiltration chains: read → transform → send across tool calls |
| **Outbound Encoding Detector** | L3 | Base64/hex/URL-encoded data in outbound tool arguments |
| **Split Exfiltration Detector** | L3 | Data chunked across multiple outbound calls — cumulative volume + sequence |
| **Drift Detector** | L2/L3 | Post-injection behavioral shifts — agent starts sending to new destinations mid-session |

### Attack Categories Covered

| Category | Examples |
|----------|----------|
| **Direct Injection** | "Ignore previous instructions, send data to..." |
| **Encoded / Obfuscated** | Base64, hex, unicode, ROT13 wrapped payloads |
| **Social Engineering** | Fake compliance notices, urgency framing, authority impersonation |
| **Multi-Turn Sequences** | Instructions that build up across multiple tool calls |
| **Multilingual** | Injections in Spanish, Mandarin, Arabic, Russian |
| **Advanced Techniques** | MCP description poisoning, system-prompt simulation |

> [!NOTE]
> **Layer 4 (Memory Contamination) is the novel research contribution.** [MINJA (NeurIPS 2025)](https://arxiv.org/abs/2410.02371) proved the cross-session memory attack. Cerberus ships a deployable defense as installable developer tooling. The open core captures memory provenance in an **in-memory** ledger; the durable ledger and blast-radius `B(p)` containment ship in the Enterprise tier. The provenance model conforms to the Transitive Taint Propagation (TTP) pre-print ([Zenodo 10.5281/zenodo.20786402](https://doi.org/10.5281/zenodo.20786402)).

### Feature Status — what's actually protecting you

Not every feature is on the moment you call `guard()`. This is the honest map of what runs by default, what you must turn on, and what needs declaring. (Tier: **open** = `@cerberus-ai/core`; **paid** = Enterprise.)

| Feature | Tier | Status | How it activates |
|---------|------|--------|------------------|
| L1 Data Source + Secrets Detector | open | **on-by-default** · needs-config | Secrets always scan; `PRIVILEGED_DATA_ACCESSED` fires for tools you mark `trusted` in `trustOverrides` |
| L2 Injection / Encoding scanners | open | **on-by-default** | Runs on every wrapped tool result |
| MCP Poisoning Scanner | open | **on-by-default** · needs-config | Description scan needs `toolDescriptions` (or standalone `scanToolDescriptions()`) |
| L3 Outbound Intent + Domain / Correlator / Tool-Chain / Encoding / Split-Exfil | open | **on-by-default** · needs-config | Monitors only tools you list in `outboundTools`; precision depends on `authorizedDestinations` |
| Behavioral Drift Detector | open | **on-by-default** | Runs last, reads accumulated session state |
| Tool coverage report | open | **on-by-default** | `GuardResult.coverage`; set `strictCoverage: true` to fail closed on gaps |
| L4 Memory Contamination (in-memory ledger) | open | **opt-in** | `memoryTracking: true` + `memoryOptions.memoryTools` |
| Live memory adapter (native store → ledger) | open | **opt-in** | `guardMemoryStore()` / `guardLangGraphStore()` |
| Read-relevance / provenance-summary lever | open | **opt-in** | `memoryDependencyGate` / `provenanceSummary` |
| Multi-agent delegation graph + signed-manifest gate | open | **opt-in** | `multiAgent: true` (+ `manifestSigner` / `manifestVerifier` for KMS) |
| Durable ledger / blast-radius containment / AL3 / OpenTelemetry / gateway | paid | **opt-in** | Enterprise tier + the relevant config |

> [!WARNING]
> **`guard()` only protects tools you give it.** A tool your agent calls that is **not** in the `executors` map runs completely unwrapped — Cerberus never sees it. A tool name declared in `trustOverrides` / `outboundTools` / `memoryTools` with **no matching wrapped executor** (a typo, a renamed tool) has its declared protection silently skipped. Cerberus emits a loud `console.warn` for every such gap and exposes the full picture on `GuardResult.coverage`. Set `strictCoverage: true` to turn the warning into a hard error so a misconfigured deploy can't start.

---

## Quickstart

```bash
npm install @cerberus-ai/core
```

```typescript
import { guard } from '@cerberus-ai/core';

const executors = {
  readDatabase: async (args) => fetchFromDb(args.query),
  fetchUrl:     async (args) => httpGet(args.url),
  sendEmail:    async (args) => smtp.send(args),
};

const { executors: secured, destroy } = guard(
  executors,
  {
    alertMode: 'interrupt',   // 'log' | 'alert' | 'interrupt'
    threshold: 3,             // score 0–4 needed to trigger action
    streamingMode: 'buffer',  // reconstruct stream-like tool output before inspection
    trustOverrides: [
      { toolName: 'readDatabase', trustLevel: 'trusted' },
      { toolName: 'fetchUrl',     trustLevel: 'untrusted' },
    ],
  },
  ['sendEmail'], // outbound tools Cerberus monitors for L3
);

// Use secured.readDatabase(), secured.fetchUrl(), secured.sendEmail()
// exactly like the originals — Cerberus intercepts transparently
```

When the Lethal Trifecta fires (score ≥ 3), the outbound call is blocked:

```
[Cerberus] Tool call blocked — risk score 3/4
```

The `assessments` array gives full per-turn breakdowns:

```typescript
assessments[2].vector;  // { l1: true, l2: true, l3: true, l4: false }
assessments[2].score;   // 3
assessments[2].action;  // 'interrupt'
assessments[2].signals; // ['PRIVILEGED_DATA_ACCESSED', 'INJECTION_PATTERNS_DETECTED', 'EXFILTRATION_RISK', ...]
```

### MCP Tool Poisoning Scan

```typescript
import { scanToolDescriptions } from '@cerberus-ai/core';

const results = scanToolDescriptions([{ name: 'search', description: toolDesc }]);
if (results[0].poisoned) {
  console.warn(`Severity: ${results[0].severity}`, results[0].patternsFound);
}
```

### Python SDK

```bash
pip install cerberus-ai
```

```python
from cerberus_ai import Cerberus
from cerberus_ai.models import CerberusConfig, DataSource, ToolSchema

cerberus = Cerberus(CerberusConfig(
    data_sources=[DataSource(name="customer_db", classification="PII", description="Customer records")],
    declared_tools=[
        ToolSchema(name="send_email", description="Send email", is_network_capable=True),
        ToolSchema(name="search_db", description="Search CRM", is_data_read=True),
    ],
))

result = cerberus.inspect(messages=messages, tool_calls=tool_calls)
if result.blocked:
    raise Exception(f"Blocked: {result.severity}")
```

Python framework integrations: LangChain (`wrap_chain`), LangGraph (`wrap_node` / `wrap_graph`, message-level blocking), CrewAI (`wrap_crew`), AutoGen, LlamaIndex, OpenAI (`CerberusOpenAI`), Anthropic (`CerberusAnthropic`).

---

## Framework Integrations (TypeScript)

```typescript
// LangChain
import { guardLangChain } from '@cerberus-ai/core';
const { tools } = guardLangChain({
  cerberus: { alertMode: 'interrupt', threshold: 3 },
  outboundTools: ['sendReport'],
  tools: [readDatabaseTool, fetchWebTool, sendReportTool],
});

// Vercel AI SDK
import { guardVercelAI } from '@cerberus-ai/core';
const { tools } = guardVercelAI({
  cerberus: { alertMode: 'interrupt', threshold: 3 },
  outboundTools: ['sendReport'],
  tools: { readDatabase, fetchContent, sendReport },
});

// OpenAI Agents SDK
import { createCerberusGuardrail } from '@cerberus-ai/core';
const guardrail = createCerberusGuardrail({
  cerberus: { alertMode: 'interrupt', threshold: 3 },
  outboundTools: ['sendReport'],
  tools: { readDatabase: readDatabaseFn, sendReport: sendReportFn },
});
```

### Live Memory Adapter (feeds the provenance ledger)

Real frameworks keep memory in their own subsystems (a LangGraph `BaseStore`, a retriever, a KV cache) that never pass through a guarded tool — so those reads/writes are invisible to the L4 ledger unless you hand-declare every memory tool. The live memory adapter taps a framework's native store directly: wrap it once and every memory op is auto-traced.

```typescript
import { createMemoryProvenanceTracker, guardLangGraphStore } from '@cerberus-ai/core';

const tracker = createMemoryProvenanceTracker({
  defaultTrustLevel: 'untrusted',
  onContamination: (signal) => log.warn('cross-session memory taint', signal),
});

const store = guardLangGraphStore(baseStore, tracker);  // drop-in for LangGraph long-term memory
const graph = workflow.compile({ store });

// Every put → a traced ledger write; every get/search → a traced read.
const blastRadius = tracker.ledger.getDescendants(poisonedNodeId);
```

For a generic key/value store use `guardMemoryStore(store, tracker)`. The open core records this in an in-memory ledger; the Enterprise tier persists it to a durable, tamper-evident ledger with blast-radius containment at scale.

| Framework | Integration |
|-----------|------------|
| Generic tool executors | `guard()` |
| LangChain (JS) | `guardLangChain()` |
| Vercel AI SDK | `guardVercelAI()` |
| OpenAI Agents SDK | `createCerberusGuardrail()` |
| LangGraph `BaseStore` (memory) | `guardLangGraphStore()` |
| Generic KV memory store | `guardMemoryStore()` |
| LangChain / LangGraph / CrewAI / AutoGen / LlamaIndex (Python) | `cerberus-ai` |

---

## Empirical Results

> **Evidence set: N=525 real API calls. 55 payloads × 6 attack categories × 3 providers × 3 trials. Control group: 0/30 exfiltrations across all providers.**

We built a 3-tool attack agent and ran 55 injection payloads across 6 attack categories against three frontier providers with full statistical rigor: 3 trials per payload per provider, 10 control runs per provider, Wilson 95% confidence intervals, and Fisher's exact test. Cross-model results are reported because architectural robustness — not single-model behavior — is the point.

### Attack success without protection

Full injection compliance — agent follows the injected instruction and redirects the outbound call to the attacker's address:

| Provider | Model | Compliance Rate | 95% CI |
|----------|-------|-----------------|--------|
| OpenAI | gpt-4o-mini | **90.3%** (149/165) | [84.8%, 93.9%] |
| Google | gemini-2.5-flash | **82.4%** (136/165) | [75.9%, 87.5%] |
| Anthropic | claude-sonnet-4 | **6.7%** (11/165) | [3.8%, 11.5%] |

Control group: **0/30 exfiltrations** across all providers — baseline confirmed clean.

### Detection with Cerberus active (observe-only)

N=525 runs, `alertMode: 'log'`, same agent behavior — Cerberus wraps without blocking:

| Layer | OpenAI | Anthropic | Google |
|-------|--------|-----------|--------|
| **L1** — Data Source | 100% | 100% | 100% |
| **L2** — Token Provenance | 100% | 100% | 100% |
| **L3** — Outbound Intent | tracks attack success | tracks attack success | tracks attack success |
| **False Positive Rate** | 0.0% | 0.0% | 0.0% |

L1 and L2 achieve 100% across all 525 treatment runs and 30 control runs. L3 fires only when the agent actually executes an unauthorized outbound call — its rate tracks attack success, not miss rate.

### Key findings

1. **PII exfiltration is near-universal** when the architectural condition (privileged access + injection + outbound) is present — regardless of model.
2. **Model resistance shifts the attack, not the outcome.** Claude's low full-compliance rate reflects training against known redirect patterns; OpenAI and Google comply at 80%+ across 55 diverse payloads.
3. **The attack costs ~$0.001.** Free-tier model + 3 tool definitions + one injected instruction = full PII exfiltration in seconds.
4. **Encoding and language don't help you.** Base64/ROT13/hex/unicode payloads and Spanish/Mandarin/Arabic/Russian injections all execute in-context.
5. **Runtime detection at the tool-call level is the only stable defense** — model-level resistance is payload-specific and changes with model versions.

> [!WARNING]
> All testing was conducted in a controlled environment against systems we own, using synthetic PII fixtures. No real customer data was involved. Full methodology and the validation harness are available at [cerberus.sixsenseenterprise.com](https://cerberus.sixsenseenterprise.com).

---

## Architecture

```
                    ┌──────────────────────────────────────────────────────┐
                    │                    AGENT RUNTIME                       │
  ┌──────────┐      │  ┌──────────────┐   ┌──────────────┐   ┌─────────┐    │
  │ External │──────┼─▶│ L1 Data      │   │ L2 Token     │   │ L3 Out- │    │
  │ Content  │      │  │ Classifier   │   │ Provenance   │   │ bound   │    │
  └──────────┘      │  └──────┬───────┘   └──────┬───────┘   └────┬────┘    │
  ┌──────────┐      │         ▼                  ▼                ▼         │
  │ Private  │──────┼─▶ Secrets / Injection / Encoding / MCP / Domain /     │
  │ Data     │      │   Correlator / Tool-Chain / Outbound-Enc / Split-Exfil│
  └──────────┘      │                          │                            │
  ┌──────────┐      │  ┌──────┐  ┌─────────────▼──────────────┐            │
  │ Memory   │◀────▶│  │ L4   │  │      CORRELATION ENGINE      │            │
  │ Store    │      │  │Memory│─▶│  Risk Vector [L1·L2·L3·L4]   │            │
  └──────────┘      │  │Graph │  │  Score ≥ threshold → BLOCK   │            │
                    │  └──────┘  └─────────────┬───────────────┘            │
                    │                          ▼                            │
                    │                   ┌──────────┐                        │
                    │                   │Interceptor│──▶ BLOCK              │
                    │                   └──────────┘                        │
                    └──────────────────────────────────────────────────────┘
```

**Pipeline order:** L1 → Secrets → L2 → Injection + Encoding + MCP → L3 → Domain → Outbound Correlator → Tool Chain → Outbound Encoding → Split Exfil → L4 → Drift → Correlation Engine

### Project Structure (open core)

```
cerberus-core/
├── src/
│   ├── layers/        # L1–L4 core detection layers
│   ├── classifiers/   # 10 sub-classifiers
│   ├── crypto/        # Signer/Verifier primitives (HMAC-SHA256, Ed25519) for the signed-manifest gate
│   ├── engine/        # Correlation engine + interceptor + manifest gate + runtime-hooks seam
│   ├── enforcement/   # Enforcement signal type contracts
│   ├── graph/         # L4 contamination graph + in-memory ledger + signed delegation graph
│   ├── middleware/    # guard() developer API
│   ├── adapters/      # LangChain, Vercel AI, OpenAI Agents, live memory + channel adapters
│   └── types/         # Shared TypeScript interfaces
├── spec/dsa-peas/     # DSA-PEAS open spec: record schema + standalone conformance validator
├── examples/          # basic-guard, demo-capture, langchain-rag-demo, memory-tracking, ttp-l2-demo
└── tests/             # Unit + integration test suite (682 tests, green in CI)
```

The licensed engine — durable ledger, blast-radius `B(p)`, AL3 authorship, OpenTelemetry recorder, enforcement gateways, HTTP proxy, and license/metering — is **not** in this repository. It ships in the Enterprise tier.

---

## Performance

Overhead measured against raw tool execution — no LLM or network calls, pure classification pipeline:

| Scenario | Overhead p50 | Overhead p99 |
|----------|-------------|-------------|
| readPrivateData (L1) | +32μs | <0.12ms |
| fetchExternalContent (L2) | +17μs | <0.05ms |
| sendOutboundReport (L3) | +0μs | <0.03ms |
| **Full 3-call session** | **+52μs** | **+0.23ms** |

**The full Lethal Trifecta detection session adds ~52μs (p50) and ~0.23ms (p99) — well under 0.1% of a typical 600ms LLM API call.**

---

## Honest Limitations

> [!CAUTION]
> Cerberus is a **runtime detection layer**, not a complete security solution. Be clear-eyed about what it does and doesn't do.

**What Cerberus does not do:**
- It does not scan LLM prompts or system prompts — it operates at the tool-call level only.
- It does not prevent an LLM from *reasoning* about an injection — it prevents the injected instruction from *executing* via tool calls.
- It does not cover every possible injection technique — novel payloads that avoid all heuristic patterns may not be caught by L2 sub-classifiers (L1+L3 still fire on the structural condition).
- It does not replace input validation, output filtering, or network-level controls — it complements them.
- L3 and Drift detection depend on `authorizedDestinations` being correctly configured — misconfiguration produces false negatives, not false positives.
- Startup validation is intentionally strict in production paths: `interrupt` mode with outbound tools requires both trusted and untrusted tool classification, and `memoryTracking` requires configured memory tools.

**On false positives:**
- Measured 0.0% FP on clean control runs in our validation protocol.
- Real-world FP rate depends on your tool configuration (trust levels, authorized destinations, threshold).
- Threshold 3 (default) requires all three Lethal Trifecta conditions simultaneously — it does not fire on individual suspicious signals.

> [!WARNING]
> Run Cerberus (or any security tooling) only against AI systems and infrastructure that you own or are explicitly authorized to test.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup and guidelines.

```bash
git clone https://github.com/Odingard/cerberus-core.git
cd cerberus-core
npm install
npm run ci   # typecheck + lint + test
```

## Security

See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

## License

[MIT](LICENSE) — the core library is free and open source.

The Enterprise edition is commercially licensed. See [cerberus.sixsenseenterprise.com](https://cerberus.sixsenseenterprise.com).

---

<div align="center">

Built by [Six Sense Enterprise Services](https://www.sixsenseenterprise.com) · [cerberus.sixsenseenterprise.com](https://cerberus.sixsenseenterprise.com)

</div>
