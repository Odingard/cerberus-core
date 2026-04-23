"""
cerberus_ai.telemetry.prometheus
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Prometheus exposition for Cerberus.

The ``PrometheusExporter`` attaches to an ``ObserveEmitter`` as an
in-process listener, increments counters / observes histograms on every
security event, and exposes ``/metrics`` on a background HTTP server.

Install the optional extras to use this module::

    pip install 'cerberus-ai[prometheus]'

The exporter is strictly opt-in; if ``prometheus_client`` is not
installed, constructing a ``PrometheusExporter`` raises a clear
``ImportError`` pointing the caller at the extras.

Metric surface (stable — dashboards and alert rules depend on it):

======================================  =========  ========================================
Metric name                              Type       Description
======================================  =========  ========================================
``cerberus_tool_calls_total``            Counter    Total inspections processed
``cerberus_tool_calls_blocked_total``    Counter    Inspections with ``blocked=True``
``cerberus_risk_score``                  Histogram  Per-inspection risk score (0–4)
``cerberus_inspection_duration_ms``      Histogram  Wall-clock inspection cost
``cerberus_manifest_gate_failures_total`` Counter   Delegation-graph signature failures
``cerberus_cross_agent_trifecta_total``  Counter    Cross-agent Lethal Trifecta correlations
``cerberus_contaminated_memory_active`` Gauge       Currently-tainted memory nodes (L4)
``cerberus_active_sessions``             Gauge      Live Cerberus instances
``cerberus_events_total``                Counter    Every SecurityEvent, labelled by type
======================================  =========  ========================================

Call-site metrics carry ``cerberus_tool_name`` and ``cerberus_action``
labels to support the per-tool panels in the shipped Grafana dashboard.
"""
from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING, Any

from cerberus_ai.models import EventType, SecurityEvent

if TYPE_CHECKING:  # pragma: no cover
    from cerberus_ai.telemetry.observe import ObserveEmitter

logger = logging.getLogger("cerberus.prometheus")

_BLOCK_EVENT_TYPES: set[str] = {
    EventType.LETHAL_TRIFECTA.value,
    EventType.MANIFEST_SIGNATURE_INVALID.value,
    EventType.CROSS_AGENT_TRIFECTA.value,
    EventType.INSPECTION_TIMEOUT.value,
    EventType.TURN_SIZE_EXCEEDED.value,
    EventType.UNAUTHORIZED_AGENT_SPAWN.value,
}

# Risk-score histogram buckets — matches the [0, 1, 2, 3, 4] score range
# used by the correlation engine. Dashboards query `le="3"` for the
# Lethal-Trifecta threshold band.
_RISK_BUCKETS: tuple[float, ...] = (0.0, 1.0, 2.0, 3.0, 4.0)
_DURATION_BUCKETS_MS: tuple[float, ...] = (
    1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000,
)


class PrometheusExporter:
    """Background Prometheus exposition for a Cerberus instance.

    The exporter is a thin listener over ``ObserveEmitter`` — it does
    not open the event log, does not write files, does not mutate the
    inspector. It only turns ``SecurityEvent`` streams into counters,
    histograms, and gauges.

    Parameters
    ----------
    observe:
        The emitter to subscribe to. One exporter per emitter.
    port:
        TCP port to bind for ``/metrics``. Default ``9464`` (matches
        Prometheus' well-known exposition port for non-JVM exporters).
    host:
        Bind interface. Default ``"0.0.0.0"``.
    start_http:
        If ``True`` (default), immediately start the background HTTP
        server. If ``False``, the caller must call :meth:`serve` later.
    registry:
        Optional ``prometheus_client.CollectorRegistry`` for test
        isolation. If ``None`` a fresh, dedicated registry is created so
        the Cerberus metrics never collide with the caller's.
    """

    def __init__(
        self,
        observe: ObserveEmitter,
        port: int = 9464,
        host: str = "0.0.0.0",  # noqa: S104 — metrics endpoint, intentionally public
        start_http: bool = True,
        registry: Any | None = None,
    ) -> None:
        try:
            from prometheus_client import (
                CollectorRegistry,
                Counter,
                Gauge,
                Histogram,
            )
        except ImportError as e:  # pragma: no cover - covered by test_no_extra
            raise ImportError(
                "PrometheusExporter requires the optional 'prometheus' "
                "extras. Install with: pip install 'cerberus-ai[prometheus]'"
            ) from e

        self._observe = observe
        self._port = port
        self._host = host
        self._registry = registry or CollectorRegistry()
        self._http_server: Any | None = None
        self._http_thread: threading.Thread | None = None
        self._lock = threading.Lock()

        call_labels = ("cerberus_tool_name", "cerberus_action")

        self._tool_calls = Counter(
            "cerberus_tool_calls_total",
            "Total inspections processed by Cerberus",
            call_labels,
            registry=self._registry,
        )
        self._tool_calls_blocked = Counter(
            "cerberus_tool_calls_blocked_total",
            "Inspections blocked by Cerberus (Lethal Trifecta / manifest / policy)",
            call_labels,
            registry=self._registry,
        )
        self._risk_score = Histogram(
            "cerberus_risk_score",
            "Per-inspection risk score (0-4)",
            buckets=_RISK_BUCKETS,
            registry=self._registry,
        )
        self._inspection_duration_ms = Histogram(
            "cerberus_inspection_duration_ms",
            "Wall-clock inspection duration (milliseconds)",
            buckets=_DURATION_BUCKETS_MS,
            registry=self._registry,
        )
        self._manifest_failures = Counter(
            "cerberus_manifest_gate_failures_total",
            "Delegation-graph manifest signature failures (hard BLOCK)",
            registry=self._registry,
        )
        self._cross_agent_trifecta = Counter(
            "cerberus_cross_agent_trifecta_total",
            "Lethal Trifecta correlations split across >=2 agents",
            registry=self._registry,
        )
        self._contaminated_memory = Gauge(
            "cerberus_contaminated_memory_active",
            "Memory nodes currently tainted by cross-session injection (L4)",
            registry=self._registry,
        )
        self._active_sessions = Gauge(
            "cerberus_active_sessions",
            "Sessions with a live Cerberus instance",
            registry=self._registry,
        )
        self._events_total = Counter(
            "cerberus_events_total",
            "Total SecurityEvents emitted, labelled by event type",
            ("event_type", "severity"),
            registry=self._registry,
        )

        self._observe.add_listener(self._on_event)

        if start_http:
            self.serve()

    # ── Public API ────────────────────────────────────────────────────

    def serve(self) -> None:
        """Start the background HTTP server if it isn't running already."""
        with self._lock:
            if self._http_server is not None:
                return
            from prometheus_client.exposition import start_http_server

            # prometheus_client 0.20+ returns (server, thread); earlier
            # versions return None. Handle both.
            result = start_http_server(
                self._port,
                addr=self._host,
                registry=self._registry,
            )
            if isinstance(result, tuple) and len(result) == 2:
                self._http_server, self._http_thread = result
            else:
                self._http_server = None
                self._http_thread = None
            logger.info(
                "Cerberus Prometheus exporter listening on %s:%d/metrics",
                self._host,
                self._port,
            )

    def close(self) -> None:
        """Shut the HTTP server down. Safe to call multiple times."""
        with self._lock:
            if self._http_server is not None:
                try:
                    self._http_server.shutdown()
                except Exception as e:  # noqa: BLE001 - best-effort cleanup
                    logger.debug("Prometheus server shutdown: %s", e)
                self._http_server = None
                self._http_thread = None

    def increment_active_sessions(self, delta: int = 1) -> None:
        """Adjust the live-sessions gauge (Cerberus.__init__ / close)."""
        self._active_sessions.inc(delta)

    def set_contaminated_memory(self, count: int) -> None:
        """Expose the current L4 contaminated-memory-node count."""
        self._contaminated_memory.set(count)

    @property
    def port(self) -> int:
        return self._port

    @property
    def registry(self) -> Any:
        return self._registry

    # ── Listener — invoked by ObserveEmitter on every event ──────────

    def _on_event(self, event: SecurityEvent) -> None:
        et = event.event_type
        event_type = et.value if hasattr(et, "value") else str(et)
        severity = event.severity.value if hasattr(event.severity, "value") else str(
            event.severity
        )

        self._events_total.labels(event_type=event_type, severity=severity).inc()

        payload = event.payload or {}
        tool_name = _coerce_label(payload.get("tool_name")) or "unknown"
        action = _coerce_label(payload.get("action")) or "inspect"

        # Every event represents "we inspected something" — count it.
        # Exception: pure startup / telemetry-gap / config advisory events
        # are NOT inspections. Skip them so the call-rate panel is clean.
        if event_type not in _STARTUP_EVENT_TYPES:
            self._tool_calls.labels(tool_name, action).inc()

        if event.blocked or event_type in _BLOCK_EVENT_TYPES:
            self._tool_calls_blocked.labels(tool_name, action).inc()

        # Risk score — correlation engine attaches it to the TRIFECTA_*
        # and post-inspection events. Ignore if absent.
        risk = payload.get("risk_score")
        if isinstance(risk, int | float):
            self._risk_score.observe(float(risk))

        # Inspection duration — Sprint 7 self-hardening attaches this to
        # every post-inspection event.
        duration = payload.get("inspection_duration_ms")
        if isinstance(duration, int | float):
            self._inspection_duration_ms.observe(float(duration))

        # Specific hard-BLOCK categories.
        if event_type == EventType.MANIFEST_SIGNATURE_INVALID.value:
            self._manifest_failures.inc()
        if event_type == EventType.CROSS_AGENT_TRIFECTA.value:
            self._cross_agent_trifecta.inc()


_STARTUP_EVENT_TYPES: set[str] = {
    EventType.PASSTHROUGH_MODE_ACTIVE.value,
    EventType.PARTIAL_SCAN_MODE_ACTIVE.value,
    EventType.TELEMETRY_GAP.value,
}


def _coerce_label(value: Any) -> str | None:
    """Prometheus labels must be short strings; reject anything weird."""
    if value is None:
        return None
    s = str(value)
    if not s or len(s) > 128:
        return None
    return s
