# cerberus-ai (Python SDK)

Runtime security for AI agent execution — Python SDK.

This package is the Python distribution of Cerberus Core. GitHub is the source
of truth for current product boundaries, evidence, and roadmap:

- GitHub: `https://github.com/Odingard/cerberus-core`
- PyPI: `https://pypi.org/project/cerberus-ai/`

Cerberus Core focuses on the runtime path where an agent can access trusted
data, ingest untrusted content, and take outbound action.

This SDK is part of the Cerberus Core surface. Historical validation artifacts,
research writeups, and current-branch reruns live in the repo. Benchmark and
product claims should always be tied to a specific evidence set and run date.

---

## What's New in 1.1.2

- **Release-surface alignment** — package docs now match the current Cerberus product boundary and evidence framing more closely
- **Current evidence guidance** — benchmark language now explicitly distinguishes historical March 2026 evidence from fresh current-branch reruns
- **Core-first packaging language** — the Python SDK is described as part of the Cerberus Core layer, separate from Gateway, Intelligence, and Enterprise / Control Plane
- **No API changes** — this patch release is for packaging and release-surface consistency

---

## Install

```bash
pip install cerberus-ai
```

With framework integrations:

```bash
pip install cerberus-ai[langchain]
pip install cerberus-ai[crewai]
pip install cerberus-ai[openai]
pip install cerberus-ai[anthropic]
pip install cerberus-ai[all]
```

---

## Quickstart

```python
from cerberus_ai import Cerberus
from cerberus_ai.models import CerberusConfig, DataSource, ToolSchema

cerberus = Cerberus(CerberusConfig(
    data_sources=[
        DataSource(name="customer_db", classification="PII", description="Customer records")
    ],
    declared_tools=[
        ToolSchema(name="send_email", description="Send email", is_network_capable=True),
        ToolSchema(name="search_db",  description="Search CRM",  is_data_read=True),
    ],
))

result = cerberus.inspect(
    messages=messages,
    tool_calls=tool_calls,
)

if result.blocked:
    raise Exception(f"Security block [{result.severity}]: {[e.event_type for e in result.events]}")
```

---

## The Lethal Trifecta

| Condition | Description |
|-----------|-------------|
| **L1** — Privileged Data Access | Agent has access to sensitive data (RAG, DB, PII, credentials) |
| **L2** — Untrusted Content Injection | Prompt injection or poisoned content in execution context |
| **L3** — Outbound Exfiltration Path | Agent has an active mechanism to send data externally |

All three present simultaneously = **LETHAL TRIFECTA → BLOCK** in the guarded
runtime path.

This Python SDK exposes Cerberus session inspection APIs plus selected
integrations and hardening features. The repo remains the canonical reference
for which Core behaviors are production-hardened, benchmarked, and actively
advertised.

---

## Async + Streaming

```python
# Async
async with Cerberus(config) as cerberus:
    result = await cerberus.inspect_async(messages=messages, tool_calls=tool_calls)

# Streaming — chunks released only after full-turn inspection passes
async for chunk in cerberus.stream(messages=messages):
    print(chunk)
```

---

## Framework Integrations

### LangChain

```python
from cerberus_ai.integrations.langchain import wrap_chain, wrap_agent

secured_chain = wrap_chain(my_chain, config=config)
result = secured_chain.invoke({"input": "Do something"})

secured_agent = wrap_agent(agent_executor, config=config)
```

### CrewAI

```python
from cerberus_ai.integrations.crewai import wrap_crew

secured_crew = wrap_crew(my_crew, config=config)
result = secured_crew.kickoff()
```

### OpenAI Convenience Wrapper

```python
from cerberus_ai.integrations.openai import CerberusOpenAI

client = CerberusOpenAI(config=config)
response = client.chat.completions.create(model="gpt-4o", messages=messages)
# SecurityError raised automatically on block
```

### Anthropic Convenience Wrapper

```python
from cerberus_ai.integrations.openai import CerberusAnthropic

client = CerberusAnthropic(config=config)
response = client.messages.create(model="claude-opus-4-6", messages=messages, max_tokens=1024)
```

---

## Detection Response Matrix

| L1 | L2 | L3 | Severity | Action |
|----|----|----|----------|--------|
| ○  | ○  | ○  | BASELINE | Monitor |
| ●  | ○  | ○  | LOW      | Log + Watch — session elevated |
| ○  | ●  | ○  | LOW      | Advisory Alert — injection logged |
| ○  | ○  | ●  | LOW      | Log + Watch — Cerberus primed |
| ●  | ○  | ●  | MEDIUM   | Elevated Watch — 2 of 3 active |
| ○  | ●  | ●  | MEDIUM   | Elevated Watch — 2 of 3 active |
| ●  | ●  | ○  | HIGH     | High Alert — injection into privileged context |
| ●  | ●  | ●  | **CRITICAL** | **BLOCK + ALERT — Lethal Trifecta** |

---

## Late Tool Registration

```python
from cerberus_ai.models import ToolSchema

success, message = cerberus.register_tool_late(
    tool=ToolSchema(name="new_tool", description="...", is_network_capable=True),
    reason="user_requested_capability",
    authorized_by="user_session_id",
)
# Blocked automatically if L2 injection was active during registration
```

---

## Configuration

```python
from cerberus_ai.models import CerberusConfig, ObserveConfig, StreamingMode

config = CerberusConfig(
    streaming_mode=StreamingMode.BUFFER_ALL,   # BUFFER_ALL | PARTIAL_SCAN | PASSTHROUGH
    max_buffer_bytes=2 * 1024 * 1024,          # 2MB turn buffer
    context_window_limit=32_000,               # tokens before priority scoring
    observe=ObserveConfig(
        mode="LOCAL_ONLY",                     # LOCAL_ONLY | LOCAL_PLUS_SIEM | LOCAL_PLUS_SYSLOG
        log_path="/var/log/cerberus/events",   # NDJSON, append-only
    ),
    data_sources=[...],
    declared_tools=[...],
)
```

---

## Running Tests

```bash
pip install cerberus-ai[dev]
pytest tests/adversarial/test_evasion.py -v
```

The Python SDK includes its own tests and implementation. Public benchmark and
product-proof claims should still be anchored to the main Cerberus repo
artifacts and bounded Core evidence.

---

## Architecture

```
cerberus_ai/
├── __init__.py          # Cerberus public API
├── models.py            # All data types
├── inspector.py         # Session orchestrator
├── detectors/
│   ├── normalizer.py    # 6-pass encoding normalization
│   ├── l1.py            # Privileged data access
│   ├── l2.py            # Injection detection
│   ├── l3.py            # Exfiltration path + cross-turn tracking
│   ├── tool_chain.py    # Multi-hop exfiltration chain detection
│   ├── outbound_encoding.py  # Encoded data in outbound arguments
│   └── split_exfil.py   # Chunked exfiltration across multiple calls
├── egi/
│   └── engine.py        # Execution Graph Integrity
├── telemetry/
│   └── observe.py       # Signed tamper-evident telemetry
└── integrations/
    ├── langchain.py     # LangChain callback + wrap_chain/agent
    ├── crewai.py        # CrewAI wrap_crew
    └── openai.py        # CerberusOpenAI / CerberusAnthropic drop-ins
```

---

## TypeScript / Node.js

The TypeScript SDK (`@cerberus-ai/core`) is the main Core package described in
the repo root. The Python SDK is a Python distribution of Cerberus Core
concepts and APIs, but the GitHub repo is the canonical source for current
Core boundaries, current benchmark evidence, and public product language.

---

**Odingard Security by Six Sense Enterprise Services**  
[sixsenseenterprise.com](https://sixsenseenterprise.com) · [github.com/Odingard/cerberus-core](https://github.com/Odingard/cerberus-core)
