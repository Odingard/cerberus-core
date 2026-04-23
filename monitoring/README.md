# Cerberus Monitoring Stack (OSS)

Self-host Grafana + Prometheus + Alertmanager + OTel Collector for
Cerberus runtime metrics. Works with both the Python SDK
(`cerberus-ai`, direct Prometheus exporter) and the TypeScript SDK
(`@cerberus-ai/core`, via OTel).

## What's Included

| Service | Port | Purpose |
|---------|------|---------|
| OTel Collector | 4317 (gRPC), 4318 (HTTP) | Receives OTLP metrics from the TS SDK |
| Prometheus | 9090 | Scrapes metrics, evaluates alert rules |
| Alertmanager | 9093 | Routes alerts (log-only default) |
| Grafana | 3030 | Pre-built Cerberus dashboard |

## Quick Start

```bash
# From the repo root
docker compose -f monitoring/docker-compose.yml up -d

# Grafana (no login required)
open http://localhost:3030
```

Prometheus UI is on `http://localhost:9090`, Alertmanager on
`http://localhost:9093`.

## Python SDK integration

```python
from cerberus_ai import Cerberus, CerberusConfig

cerberus = Cerberus(CerberusConfig(
    prometheus_enabled=True,
    prometheus_port=9464,   # default
))
```

The SDK starts a background HTTP server on the given port and exposes
`/metrics` in the Prometheus exposition format. The default Prometheus
scrape target `host.docker.internal:9464` picks it up automatically on
macOS / Windows. On Linux, either run the app in a container on the
`cerberus-monitoring` docker network or set
`CERBERUS_PROMETHEUS_TARGET` in `prometheus.yml`.

Install the exporter extras:

```bash
pip install 'cerberus-ai[prometheus]'
```

## TypeScript SDK integration

Install the OTel SDK packages:

```bash
npm install @opentelemetry/sdk-trace-node @opentelemetry/sdk-metrics \
  @opentelemetry/exporter-trace-otlp-http @opentelemetry/exporter-metrics-otlp-http \
  @opentelemetry/sdk-trace-base
```

Configure your app before calling `guard()`:

```typescript
import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { MeterProvider, PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { metrics } from '@opentelemetry/api';
import { guard } from '@cerberus-ai/core';

const traceProvider = new NodeTracerProvider({
  spanProcessors: [new BatchSpanProcessor(new OTLPTraceExporter({
    url: 'http://localhost:4318/v1/traces',
  }))],
});
traceProvider.register();

const meterProvider = new MeterProvider({
  readers: [new PeriodicExportingMetricReader({
    exporter: new OTLPMetricExporter({ url: 'http://localhost:4318/v1/metrics' }),
    exportIntervalMillis: 5000,
  })],
});
metrics.setGlobalMeterProvider(meterProvider);

const { executors } = guard(myTools, {
  alertMode: 'interrupt',
  threshold: 3,
  opentelemetry: true,
});
```

Prometheus strips the OTel `cerberus_cerberus_*` double prefix
automatically (via `metric_relabel_configs` in `prometheus.yml`), so
the dashboard and alerts use the clean `cerberus_*` naming for both
SDKs.

## Dashboard Panels

| Panel | What It Shows |
|-------|--------------|
| Total Tool Calls | Cumulative call count over selected time range |
| Blocked Calls | Count of interrupt-action calls |
| Block Rate | % of calls that were blocked |
| Avg Risk Score | Mean risk score (0–4) across all calls |
| High-Risk Calls | Calls with score ≥ 3 (Lethal Trifecta threshold) |
| Tool Call Rate | calls/sec — total vs blocked, over time |
| Current Block Rate | Gauge showing real-time block % |
| Avg Risk Score Over Time | Risk score trend line |
| Risk Score Histogram | Distribution across score buckets |
| Call Rate by Tool | Per-tool throughput |
| Block Rate by Tool | Which tools are getting blocked |
| Per-Tool Summary Table | Total/blocked/block-rate per tool, sorted by risk |
| Calls by Action (stacked) | none/log/alert/interrupt breakdown over time |
| Action Breakdown | Current window bar gauge |

## Metrics Reference

The Python SDK direct exporter emits:

| Metric | Type | Description |
|--------|------|-------------|
| `cerberus_tool_calls_total` | Counter | Every inspection processed |
| `cerberus_tool_calls_blocked_total` | Counter | Inspections where `blocked=True` |
| `cerberus_risk_score` | Histogram | Risk score per inspection (0–4) |
| `cerberus_inspection_duration_ms` | Histogram | Wall-clock cost of an inspection |
| `cerberus_manifest_gate_failures_total` | Counter | Delegation-graph manifest verification failures |
| `cerberus_cross_agent_trifecta_total` | Counter | Cross-agent Lethal Trifecta correlation events |
| `cerberus_contaminated_memory_active_total` | Gauge | Memory nodes currently tainted by L4 |
| `cerberus_active_sessions` | Gauge | Sessions with a live Cerberus instance |

Labels on call-site metrics: `cerberus_tool_name`, `cerberus_action`.

The TS SDK (via OTel) emits equivalent metrics under the
`cerberus_cerberus_*` namespace; Prometheus rewrites them to
`cerberus_*` on scrape.

## Alerts

Seven alert rules ship in `alerts.yml`, evaluated every 30 seconds:

| Alert | Severity | Condition |
|-------|----------|-----------|
| `CerberusLethalTrifectaDetected` | critical | Any call blocked in last 5 min |
| `CerberusManifestGateFailure` | critical | Manifest signature failed to verify |
| `CerberusCrossAgentTrifecta` | critical | L1+L2+L3 split across ≥2 agents |
| `CerberusBlockRateCritical` | critical | Block rate > 50% for 1 min |
| `CerberusBlockRateHigh` | warning | Block rate > 10% for 2 min |
| `CerberusRiskScoreElevated` | warning | Avg risk score ≥ 2 for 10 min |
| `CerberusHighCallVolume` | warning | Call rate > 100/sec for 5 min |
| `CerberusMetricsMissing` | warning | No metrics received for 5 min |

Alerts fire in Prometheus and are visible in Grafana's Alerting tab.
To route to Slack, PagerDuty, or email, edit `alertmanager.yml` —
the receivers section has commented-out templates for each.

Alertmanager UI: `http://localhost:9093`.

## Stopping

```bash
docker compose -f monitoring/docker-compose.yml down

# Remove volumes too:
docker compose -f monitoring/docker-compose.yml down -v
```
