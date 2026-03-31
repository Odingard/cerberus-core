# Cerberus Core

Runtime security for AI agent tool execution.

[![CI](https://github.com/Odingard/cerberus-core/actions/workflows/ci.yml/badge.svg)](https://github.com/Odingard/cerberus-core/actions/workflows/ci.yml)
[![Python SDK](https://github.com/Odingard/cerberus-core/actions/workflows/python-sdk.yml/badge.svg)](https://github.com/Odingard/cerberus-core/actions/workflows/python-sdk.yml)
[![npm version](https://img.shields.io/npm/v/@cerberus-ai/core.svg)](https://www.npmjs.com/package/@cerberus-ai/core)
[![PyPI version](https://img.shields.io/pypi/v/cerberus-ai.svg)](https://pypi.org/project/cerberus-ai/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Cerberus Core is the embeddable runtime enforcement layer for AI agents. It correlates privileged data access, untrusted content ingestion, and outbound behavior at the tool-call level, then interrupts guarded outbound actions before they execute.

## Install

```bash
npm install @cerberus-ai/core
# or
pip install cerberus-ai
```

## Documentation

- [Getting Started](docs/getting-started.md)

## TypeScript Quickstart

```ts
import { guard } from '@cerberus-ai/core';

const { executors: secured } = guard(
  {
    readDatabase: async (args) => fetchFromDb(args.query),
    fetchUrl: async (args) => httpGet(args.url),
    sendEmail: async (args) => smtp.send(args),
  },
  {
    alertMode: 'interrupt',
    threshold: 3,
    trustOverrides: [
      { toolName: 'readDatabase', trustLevel: 'trusted' },
      { toolName: 'fetchUrl', trustLevel: 'untrusted' },
    ],
  },
  ['sendEmail'],
);
```

## Python Quickstart

```python
from cerberus_ai import Cerberus
from cerberus_ai.models import CerberusConfig, DataSource, ToolSchema

cerberus = Cerberus(CerberusConfig(
    data_sources=[DataSource(name="customer_db", classification="PII", description="Customer records")],
    declared_tools=[
        ToolSchema(name="search_db", description="Search CRM", is_data_read=True),
        ToolSchema(name="send_email", description="Send email", is_network_capable=True),
    ],
))
```

## What Core Includes

- TypeScript SDK in `src/`
- Python SDK in `sdk/python/`
- test suites in `tests/`
- minimal examples in `examples/`

## What Core Does Not Include

This repository is intentionally limited to the public Core SDK surface.

Enterprise gateway, monitoring, commercial deployment tooling, hosted product operations, deep validation trace corpora, and licensing infrastructure belong in separate private product infrastructure.

## License

MIT. See [LICENSE](LICENSE).
