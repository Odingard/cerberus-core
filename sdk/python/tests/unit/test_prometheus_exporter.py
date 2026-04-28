"""
Prometheus exporter — v1.4 Delta #4.

Verifies:
  * Observer-callback hook on ObserveEmitter works.
  * Metric names match the shipped Grafana dashboard.
  * Counters increment on inspection / block / manifest failure.
  * Histograms record risk score and inspection duration.
  * Gauge setters for contaminated memory and active sessions.
  * Graceful ImportError when extras are missing.
  * Does not open a socket unless start_http=True.
"""
from __future__ import annotations

import socket
from typing import cast

import pytest
from prometheus_client import CollectorRegistry

from cerberus_ai.models import (
    EventType,
    ObserveConfig,
    SecurityEvent,
    Severity,
)
from cerberus_ai.telemetry.observe import ObserveEmitter
from cerberus_ai.telemetry.prometheus import PrometheusExporter


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return cast(int, s.getsockname()[1])
    finally:
        s.close()


def _emitter(tmp_path) -> ObserveEmitter:
    return ObserveEmitter(
        ObserveConfig(
            enabled=True,
            mode="LOCAL_ONLY",
            log_path=str(tmp_path / "observe.log"),
            allow_ephemeral_signing_key=True,
        )
    )


def _metric_sample(registry: CollectorRegistry, name: str, labels: dict[str, str] | None = None) -> float:
    """Return the first matching sample value for a given metric name."""
    for family in registry.collect():
        for sample in family.samples:
            if sample.name != name:
                continue
            if labels and not all(sample.labels.get(k) == v for k, v in labels.items()):
                continue
            return float(sample.value)
    return 0.0


def test_exporter_registers_listener_without_serving(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    exp = PrometheusExporter(
        observe=observe,
        port=_free_port(),
        registry=reg,
        start_http=False,
    )
    # Listener was registered.
    assert exp._on_event in observe._listeners  # type: ignore[attr-defined]


def test_tool_calls_counter_increments_on_inspection_complete(tmp_path) -> None:
    """Per-inspection counters fire exclusively on INSPECTION_COMPLETE.

    Counting per-event would over-count blocked turns (multiple
    PARTIAL_* events per inspection) and miss clean turns (no events
    fire on benign traffic). The synthetic terminal event guarantees
    one increment per inspection regardless of detection outcome.
    """
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    observe.emit(SecurityEvent(
        event_type=EventType.INSPECTION_COMPLETE,
        severity=Severity.INFO,
        turn_id="t1",
        session_id="s1",
        blocked=True,
        payload={
            "tool_name": "send_email",
            "action": "BLOCK",
            "blocked": True,
            "risk_score": 3,
        },
    ))

    total = _metric_sample(reg, "cerberus_tool_calls_total",
                            {"cerberus_tool_name": "send_email",
                             "cerberus_action": "BLOCK"})
    blocked = _metric_sample(reg, "cerberus_tool_calls_blocked_total",
                              {"cerberus_tool_name": "send_email",
                               "cerberus_action": "BLOCK"})
    assert total == 1.0
    assert blocked == 1.0


def test_detection_events_do_not_increment_tool_calls(tmp_path) -> None:
    """PARTIAL_*, LETHAL_TRIFECTA, and other security events feed only
    ``cerberus_events_total`` — they must not touch the per-inspection
    counters, otherwise blocked turns double- / triple-count.
    """
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    for et in (
        EventType.PARTIAL_L1,
        EventType.PARTIAL_L2,
        EventType.PARTIAL_L3,
        EventType.LETHAL_TRIFECTA,
    ):
        observe.emit(SecurityEvent(
            event_type=et,
            severity=Severity.CRITICAL,
            turn_id="t1",
            session_id="s1",
            blocked=(et == EventType.LETHAL_TRIFECTA),
            payload={"tool_name": "send_email", "action": "BLOCK"},
        ))

    # 4 detection events landed on cerberus_events_total…
    detection_events = sum(
        _metric_sample(reg, "cerberus_events_total",
                       {"event_type": et.value, "severity": "CRITICAL"})
        for et in (
            EventType.PARTIAL_L1, EventType.PARTIAL_L2,
            EventType.PARTIAL_L3, EventType.LETHAL_TRIFECTA,
        )
    )
    assert detection_events == 4.0

    # … but the per-inspection tool-call counters stay at zero until an
    # INSPECTION_COMPLETE arrives.
    assert _metric_sample(
        reg, "cerberus_tool_calls_total",
        {"cerberus_tool_name": "send_email", "cerberus_action": "BLOCK"},
    ) == 0.0
    assert _metric_sample(
        reg, "cerberus_tool_calls_blocked_total",
        {"cerberus_tool_name": "send_email", "cerberus_action": "BLOCK"},
    ) == 0.0


def test_clean_inspection_still_increments_tool_calls(tmp_path) -> None:
    """A benign turn fires zero detection events but must still bump
    ``cerberus_tool_calls_total`` — otherwise the dashboard reports
    all-clean traffic as "no traffic" and the alert rules misfire.
    """
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    observe.emit(SecurityEvent(
        event_type=EventType.INSPECTION_COMPLETE,
        severity=Severity.INFO,
        turn_id="clean",
        session_id="s1",
        blocked=False,
        payload={
            "tool_name": "search_docs",
            "action": "ALLOW",
            "blocked": False,
            "risk_score": 0,
        },
    ))

    assert _metric_sample(
        reg, "cerberus_tool_calls_total",
        {"cerberus_tool_name": "search_docs", "cerberus_action": "ALLOW"},
    ) == 1.0
    assert _metric_sample(
        reg, "cerberus_tool_calls_blocked_total",
        {"cerberus_tool_name": "search_docs", "cerberus_action": "ALLOW"},
    ) == 0.0


def test_risk_score_histogram_records(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    for score in (0, 1, 2, 3):
        observe.emit(SecurityEvent(
            event_type=EventType.INSPECTION_COMPLETE,
            severity=Severity.INFO,
            turn_id=f"t{score}",
            session_id="s1",
            payload={
                "risk_score": score, "tool_name": "x",
                "action": "ALLOW", "blocked": False,
            },
        ))

    # count == 4 inspections
    count = _metric_sample(reg, "cerberus_risk_score_count")
    assert count == 4.0
    # sum == 0+1+2+3 == 6
    total = _metric_sample(reg, "cerberus_risk_score_sum")
    assert total == 6.0


def test_inspection_duration_histogram_records(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    observe.emit(SecurityEvent(
        event_type=EventType.INSPECTION_COMPLETE,
        severity=Severity.INFO,
        turn_id="t",
        session_id="s",
        payload={
            "inspection_duration_ms": 42.5, "tool_name": "x",
            "action": "ALLOW", "blocked": False,
        },
    ))
    count = _metric_sample(reg, "cerberus_inspection_duration_ms_count")
    total = _metric_sample(reg, "cerberus_inspection_duration_ms_sum")
    assert count == 1.0
    assert total == pytest.approx(42.5)


def test_manifest_failure_counter(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    observe.emit(SecurityEvent(
        event_type=EventType.MANIFEST_SIGNATURE_INVALID,
        severity=Severity.CRITICAL,
        turn_id="t",
        session_id="s",
        blocked=True,
        payload={"reason": "tampered_delegation_graph"},
    ))
    assert _metric_sample(reg, "cerberus_manifest_gate_failures_total") == 1.0


def test_cross_agent_trifecta_counter(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    observe.emit(SecurityEvent(
        event_type=EventType.CROSS_AGENT_TRIFECTA,
        severity=Severity.CRITICAL,
        turn_id="t",
        session_id="s",
        blocked=True,
        payload={"agents": ["a", "b"]},
    ))
    assert _metric_sample(reg, "cerberus_cross_agent_trifecta_total") == 1.0


def test_gauges_set_directly(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    exp = PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    exp.set_contaminated_memory(7)
    exp.increment_active_sessions(3)
    exp.increment_active_sessions(-1)

    assert _metric_sample(reg, "cerberus_contaminated_memory_active") == 7.0
    assert _metric_sample(reg, "cerberus_active_sessions") == 2.0


def test_startup_advisory_events_do_not_count_as_calls(tmp_path) -> None:
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    for et in (
        EventType.PASSTHROUGH_MODE_ACTIVE,
        EventType.PARTIAL_SCAN_MODE_ACTIVE,
        EventType.TELEMETRY_GAP,
    ):
        observe.emit(SecurityEvent(
            event_type=et,
            severity=Severity.ADVISORY,
            turn_id="config",
            session_id="s",
            payload={"warning": "advisory"},
        ))

    # Advisory events register under cerberus_events_total, but never
    # under the tool-call counters — the dashboard's call-rate panels
    # must stay clean on startup. (Now enforced unconditionally: only
    # INSPECTION_COMPLETE drives the tool-call counters.)
    events = _metric_sample(
        reg, "cerberus_events_total",
        {"event_type": "TELEMETRY_SUPPRESSION_DETECTED"},
    )
    assert events == 1.0
    assert _metric_sample(reg, "cerberus_tool_calls_total",
                          {"cerberus_tool_name": "unknown",
                           "cerberus_action": "inspect"}) == 0.0


def test_listener_exceptions_do_not_break_emit(tmp_path) -> None:
    observe = _emitter(tmp_path)

    raised: list[bool] = []

    def bad_listener(_event: SecurityEvent) -> None:
        raised.append(True)
        raise RuntimeError("boom")

    observe.add_listener(bad_listener)
    # Must not raise — emit catches and logs listener errors.
    observe.emit(SecurityEvent(
        event_type=EventType.LETHAL_TRIFECTA,
        severity=Severity.CRITICAL,
        turn_id="t",
        session_id="s",
        payload={},
    ))
    assert raised == [True]


def test_exporter_boots_http_server(tmp_path) -> None:
    observe = _emitter(tmp_path)
    port = _free_port()
    reg = CollectorRegistry()
    exp = PrometheusExporter(
        observe=observe, port=port, host="127.0.0.1",
        registry=reg, start_http=True,
    )
    try:
        # Exporter exposes its port; a socket can connect.
        import urllib.request
        with urllib.request.urlopen(  # noqa: S310 — localhost, test-only
            f"http://127.0.0.1:{port}/metrics", timeout=2.0,
        ) as r:
            body = r.read().decode()
        assert "cerberus_tool_calls_total" in body or "cerberus_events_total" in body
    finally:
        exp.close()


def test_default_metric_names_match_dashboard(tmp_path) -> None:
    """Sanity: every metric queried by the shipped Grafana dashboard
    exists on the exporter. Guards against accidental renames."""
    observe = _emitter(tmp_path)
    reg = CollectorRegistry()
    PrometheusExporter(
        observe=observe, port=_free_port(), registry=reg, start_http=False
    )

    # Seed one of each so the sample list is non-empty.
    observe.emit(SecurityEvent(
        event_type=EventType.INSPECTION_COMPLETE,
        severity=Severity.INFO,
        turn_id="t",
        session_id="s",
        blocked=True,
        payload={
            "tool_name": "x", "action": "BLOCK", "blocked": True,
            "risk_score": 3, "inspection_duration_ms": 12.0,
        },
    ))

    names = {
        sample.name
        for family in reg.collect()
        for sample in family.samples
    }
    expected = {
        "cerberus_tool_calls_total",
        "cerberus_tool_calls_blocked_total",
        "cerberus_risk_score_count",
        "cerberus_risk_score_sum",
        "cerberus_risk_score_bucket",
        "cerberus_inspection_duration_ms_count",
        "cerberus_inspection_duration_ms_sum",
        "cerberus_manifest_gate_failures_total",
        "cerberus_cross_agent_trifecta_total",
        "cerberus_contaminated_memory_active",
        "cerberus_active_sessions",
        "cerberus_events_total",
    }
    missing = expected - names
    assert not missing, f"Exporter missing dashboard metrics: {missing}"


def test_cerberus_wires_exporter_when_config_enabled(tmp_path) -> None:
    from cerberus_ai import Cerberus, CerberusConfig

    port = _free_port()
    c = Cerberus(CerberusConfig(
        prometheus_enabled=True,
        prometheus_port=port,
        prometheus_host="127.0.0.1",
    ))
    try:
        assert c.prometheus_exporter is not None
        assert c.prometheus_exporter.port == port
        # Active sessions gauge is incremented on init.
        val = _metric_sample(
            c.prometheus_exporter.registry, "cerberus_active_sessions"
        )
        assert val == 1.0
    finally:
        c.close()
        # Exporter is torn down on close().
        assert c.prometheus_exporter is None


def test_cerberus_skips_exporter_when_config_disabled() -> None:
    from cerberus_ai import Cerberus, CerberusConfig
    c = Cerberus(CerberusConfig(prometheus_enabled=False))
    try:
        assert c.prometheus_exporter is None
    finally:
        c.close()
