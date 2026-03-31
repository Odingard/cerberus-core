/**
 * OpenTelemetry instrumentation for Cerberus.
 *
 * Emits one span and updates three metrics per tool call when
 * `opentelemetry: true` is set in CerberusConfig.
 *
 * This module always imports `@opentelemetry/api` — it is a zero-cost
 * no-op singleton when no OTel SDK/exporter is registered by the host app.
 * Overhead when disabled: a single boolean check per tool call.
 *
 * Span: cerberus.tool_call
 * Metrics:
 *   cerberus.tool_calls.total   — counter (all calls)
 *   cerberus.tool_calls.blocked — counter (blocked calls only)
 *   cerberus.risk_score         — histogram (0–4)
 *
 * Attributes on every span/metric:
 *   cerberus.tool_name          — name of the tool that was called
 *   cerberus.session_id         — Cerberus session identifier
 *   cerberus.turn_id            — turn identifier within the session
 *   cerberus.risk_score         — cumulative risk score (0–4)
 *   cerberus.action             — 'log' | 'alert' | 'interrupt'
 *   cerberus.blocked            — true when action was interrupt
 *   cerberus.signals_detected   — comma-separated signal names
 *   cerberus.duration_ms        — total wall time including tool execution
 *
 * Setup (user's app):
 *   import { NodeTracerProvider } from '@opentelemetry/sdk-trace-node';
 *   import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
 *   const provider = new NodeTracerProvider({ ... });
 *   provider.addSpanProcessor(new BatchSpanProcessor(new OTLPTraceExporter()));
 *   provider.register();
 *   // Then just add opentelemetry: true to your CerberusConfig.
 */

import { trace, metrics, SpanStatusCode } from '@opentelemetry/api';
import type { Attributes, Counter, Histogram } from '@opentelemetry/api';

const INSTRUMENTATION_NAME = '@cerberus-ai/core';
const INSTRUMENTATION_VERSION = '0.3.1';

// Metric instruments — lazily created on first tool call with OTel enabled.
// Using module-level variables means they're created once per process.
let _toolCallsTotal: Counter | null = null;
let _toolCallsBlocked: Counter | null = null;
let _riskScore: Histogram | null = null;

function ensureMetrics(): void {
  if (_toolCallsTotal) return;
  const meter = metrics.getMeter(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
  _toolCallsTotal = meter.createCounter('cerberus.tool_calls.total', {
    description: 'Total number of AI agent tool calls processed by Cerberus',
  });
  _toolCallsBlocked = meter.createCounter('cerberus.tool_calls.blocked', {
    description: 'Number of tool calls blocked by Cerberus (risk score ≥ threshold)',
  });
  _riskScore = meter.createHistogram('cerberus.risk_score', {
    description: 'Risk score (0–4) for each tool call',
    unit: '1',
    // Explicit boundaries ensure le="0","1","2","3","4" buckets exist in Prometheus
    // so that Grafana "High-Risk Calls (score ≥ 3)" queries work correctly.
    // Default OTel boundaries are latency-oriented (0,5,10,25,50ms…) and miss these values.
    advice: { explicitBucketBoundaries: [0, 1, 2, 3, 4] },
  });
}

/** Data captured per tool call for telemetry export. */
export interface ToolCallRecord {
  readonly toolName: string;
  readonly sessionId: string;
  readonly turnId: string;
  readonly score: number;
  readonly action: string;
  readonly blocked: boolean;
  readonly signals: readonly string[];
  readonly durationMs: number;
}

/**
 * Record one tool call: create a span and update metrics.
 *
 * Safe to call when no OTel SDK is configured — all operations are
 * no-ops via the OTel API's built-in ProxyTracerProvider / ProxyMeterProvider.
 */
export function recordToolCall(data: ToolCallRecord): void {
  const spanAttrs: Attributes = {
    'cerberus.tool_name': data.toolName,
    'cerberus.session_id': data.sessionId,
    'cerberus.turn_id': data.turnId,
    'cerberus.risk_score': data.score,
    'cerberus.action': data.action,
    'cerberus.blocked': data.blocked,
    'cerberus.signals_detected': data.signals.join(','),
    'cerberus.duration_ms': data.durationMs,
  };

  const tracer = trace.getTracer(INSTRUMENTATION_NAME, INSTRUMENTATION_VERSION);
  const span = tracer.startSpan('cerberus.tool_call', { attributes: spanAttrs });
  span.setStatus(
    data.blocked
      ? { code: SpanStatusCode.ERROR, message: 'Tool call blocked by Cerberus' }
      : { code: SpanStatusCode.OK },
  );
  span.end();

  ensureMetrics();
  const metricAttrs: Attributes = {
    'cerberus.tool_name': data.toolName,
    'cerberus.action': data.action,
  };
  _toolCallsTotal!.add(1, metricAttrs);
  if (data.blocked) _toolCallsBlocked!.add(1, metricAttrs);
  _riskScore!.record(data.score, metricAttrs);
}

/**
 * Reset metric instrument singletons.
 * Only used in tests to allow re-registration with a fresh meter provider.
 * @internal
 */
export function _resetMetricsForTest(): void {
  _toolCallsTotal = null;
  _toolCallsBlocked = null;
  _riskScore = null;
}
