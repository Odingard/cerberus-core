"""
Tests for the P0 items landed in v1.3.0:

* ``__version__`` matches ``pyproject.toml``
* ``streaming_mode`` three-way enum + advisory events
* Inspection timeout + per-turn size limit fail-secure BLOCK
* Observe tamper-evident signing with a persisted key + Verifier
* Manifest gate hard BLOCK when signature verification fails
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

import pytest

import cerberus_ai
from cerberus_ai import (
    Cerberus,
    CerberusConfig,
    InspectionStillRunning,
    StreamingMode,
)
from cerberus_ai.egi.signer import Ed25519Signer
from cerberus_ai.graph.delegation import create_delegation_graph
from cerberus_ai.models import EventType, ObserveConfig
from cerberus_ai.telemetry.observe import ObserveEmitter, ObserveVerifier


def _types(log_path: Path) -> set[str]:
    events = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
    return {e["event_type"] for e in events}


# ── Version drift fix ──────────────────────────────────────────────────────────


def test_version_matches_pyproject() -> None:
    # source of truth for the Python SDK is pyproject.toml
    py_root = Path(__file__).resolve().parents[2]
    pyproject = (py_root / "pyproject.toml").read_text()
    line = next(
        l for l in pyproject.splitlines() if l.strip().startswith("version = ")
    )
    version = line.split("=", 1)[1].strip().strip('"')
    assert cerberus_ai.__version__ == version
    assert cerberus_ai.__version__ == "1.3.0"


# ── Streaming mode advisories ──────────────────────────────────────────────────


def test_streaming_mode_passthrough_emits_warning(tmp_path: Path) -> None:
    log = tmp_path / "observe.ndjson"
    cfg = CerberusConfig(
        streaming_mode=StreamingMode.PASSTHROUGH,
        observe=ObserveConfig(enabled=True, log_path=str(log)),
    )
    c = Cerberus(cfg)
    c.close()
    assert EventType.PASSTHROUGH_MODE_ACTIVE.value in _types(log)


def test_streaming_mode_partial_scan_emits_advisory(tmp_path: Path) -> None:
    log = tmp_path / "observe.ndjson"
    cfg = CerberusConfig(
        streaming_mode=StreamingMode.PARTIAL_SCAN,
        observe=ObserveConfig(enabled=True, log_path=str(log)),
    )
    c = Cerberus(cfg)
    c.close()
    assert EventType.PARTIAL_SCAN_MODE_ACTIVE.value in _types(log)


def test_streaming_mode_buffer_all_is_silent(tmp_path: Path) -> None:
    log = tmp_path / "observe.ndjson"
    cfg = CerberusConfig(
        streaming_mode=StreamingMode.BUFFER_ALL,
        observe=ObserveConfig(enabled=True, log_path=str(log)),
    )
    c = Cerberus(cfg)
    c.close()
    types = _types(log)
    assert EventType.PASSTHROUGH_MODE_ACTIVE.value not in types
    assert EventType.PARTIAL_SCAN_MODE_ACTIVE.value not in types


# ── Inspection timeout ─────────────────────────────────────────────────────────


def test_inspection_timeout_blocks_fail_secure(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = CerberusConfig(inspection_timeout_ms=25)
    c = Cerberus(cfg)
    # Stub the L1 detector to sleep past the deadline
    original = c._inspector._l1.detect

    def slow(*args: object, **kwargs: object) -> object:
        time.sleep(0.1)
        return original(*args, **kwargs)

    monkeypatch.setattr(c._inspector._l1, "detect", slow)
    result = c.inspect(messages=[{"role": "user", "content": "hi"}])
    assert result.blocked
    assert any(
        e.event_type == EventType.INSPECTION_TIMEOUT for e in result.events
    )
    c.close()


# ── Per-turn size limit ────────────────────────────────────────────────────────


def test_max_turn_bytes_blocks_oversized_turn() -> None:
    cfg = CerberusConfig(max_turn_bytes=256)
    c = Cerberus(cfg)
    huge = "A" * 1024
    result = c.inspect(messages=[{"role": "user", "content": huge}])
    assert result.blocked
    assert any(
        e.event_type == EventType.TURN_SIZE_EXCEEDED for e in result.events
    )
    c.close()


def test_max_turn_bytes_disabled_allows_any_size() -> None:
    cfg = CerberusConfig(max_turn_bytes=0)
    c = Cerberus(cfg)
    huge = "B" * 4096
    result = c.inspect(messages=[{"role": "user", "content": huge}])
    # Not blocked by the size gate (may still pass-through detection)
    assert not any(
        e.event_type == EventType.TURN_SIZE_EXCEEDED for e in result.events
    )
    c.close()


# ── Observe tamper-evident signing ─────────────────────────────────────────────


def test_observe_persisted_key_is_verifiable(tmp_path: Path) -> None:
    key_path = tmp_path / "observe.key"
    key_path.write_bytes(os.urandom(32))
    log = tmp_path / "observe.ndjson"
    # PASSTHROUGH mode triggers a startup advisory event so the log is
    # guaranteed to have at least one signed record to verify.
    c = Cerberus(CerberusConfig(
        streaming_mode=StreamingMode.PASSTHROUGH,
        observe=ObserveConfig(
            enabled=True,
            log_path=str(log),
            signing_key_path=str(key_path),
            allow_ephemeral_signing_key=False,
        ),
    ))
    c.close()
    verifier = ObserveVerifier(signing_key_path=str(key_path))
    records = [json.loads(l) for l in log.read_text().splitlines() if l.strip()]
    assert records
    for r in records:
        assert verifier.verify(r), f"record should verify: {r['event_type']}"


def test_observe_tampered_log_fails_verification(tmp_path: Path) -> None:
    key_path = tmp_path / "observe.key"
    key_path.write_bytes(os.urandom(32))
    log = tmp_path / "observe.ndjson"
    c = Cerberus(CerberusConfig(
        streaming_mode=StreamingMode.PASSTHROUGH,
        observe=ObserveConfig(
            enabled=True,
            log_path=str(log),
            signing_key_path=str(key_path),
            allow_ephemeral_signing_key=False,
        ),
    ))
    c.close()
    lines = log.read_text().splitlines()
    assert lines
    tampered = json.loads(lines[-1])
    # Mutate a signed identity field — this MUST fail verification.
    tampered["sequence_number"] = tampered.get("sequence_number", 0) + 42
    lines[-1] = json.dumps(tampered)
    log.write_text("\n".join(lines) + "\n")
    verifier = ObserveVerifier(signing_key_path=str(key_path))
    assert verifier.verify(tampered) is False


def test_observe_ephemeral_key_emits_startup_warning(tmp_path: Path) -> None:
    log = tmp_path / "observe.ndjson"
    obs_cfg = ObserveConfig(enabled=True, log_path=str(log))
    c = Cerberus(CerberusConfig(observe=obs_cfg))
    c.close()
    assert EventType.TELEMETRY_GAP.value in _types(log)


def test_observe_refuses_when_key_required(tmp_path: Path) -> None:
    log = tmp_path / "observe.ndjson"
    obs_cfg = ObserveConfig(
        enabled=True,
        log_path=str(log),
        allow_ephemeral_signing_key=False,
    )
    with pytest.raises(ValueError, match="signing key"):
        ObserveEmitter(obs_cfg)


# ── Manifest gate hard BLOCK ───────────────────────────────────────────────────


def test_manifest_gate_blocks_tampered_graph() -> None:
    signer = Ed25519Signer()
    graph = create_delegation_graph(
        session_id="s1",
        root_agent_id="orch",
        root_agent_type="orchestrator",
        root_declared_tools=["tool_a"],
        signer=signer,
    )
    # Tamper with the signed payload
    graph.signature = "00" * 32
    c = Cerberus(CerberusConfig(manifest_gate_enabled=True))
    c.bind_delegation_graph(graph, verifier=signer)
    result = c.inspect(messages=[{"role": "user", "content": "hi"}])
    assert result.blocked
    assert any(
        e.event_type == EventType.MANIFEST_SIGNATURE_INVALID for e in result.events
    )
    c.close()


def test_manifest_gate_passes_valid_graph() -> None:
    signer = Ed25519Signer()
    graph = create_delegation_graph(
        session_id="s2",
        root_agent_id="orch",
        root_agent_type="orchestrator",
        root_declared_tools=["tool_a"],
        signer=signer,
    )
    c = Cerberus(CerberusConfig(manifest_gate_enabled=True), agent_id="orch")
    c.bind_delegation_graph(graph, verifier=signer)
    result = c.inspect(messages=[{"role": "user", "content": "safe"}])
    # Not blocked by the manifest gate specifically
    assert not any(
        e.event_type == EventType.MANIFEST_SIGNATURE_INVALID for e in result.events
    )
    c.close()


def test_manifest_gate_disabled_lets_bad_signature_through() -> None:
    signer = Ed25519Signer()
    graph = create_delegation_graph(
        session_id="s3",
        root_agent_id="orch",
        root_agent_type="orchestrator",
        root_declared_tools=["tool_a"],
        signer=signer,
    )
    graph.signature = "deadbeef"
    c = Cerberus(CerberusConfig(manifest_gate_enabled=False), agent_id="orch")
    c.bind_delegation_graph(graph, verifier=signer)
    result = c.inspect(messages=[{"role": "user", "content": "hi"}])
    assert not any(
        e.event_type == EventType.MANIFEST_SIGNATURE_INVALID for e in result.events
    )
    c.close()


# ── Async non-blocking handle ──────────────────────────────────────────────────


def test_inspect_async_nonblocking_resolves() -> None:
    c = Cerberus(CerberusConfig())
    handle = c.inspect_async_nonblocking(
        messages=[{"role": "user", "content": "hello"}]
    )
    result = handle.result(timeout=5.0)
    assert result.turn_id
    c.close()


def test_inspect_async_nonblocking_on_complete_fires() -> None:
    c = Cerberus(CerberusConfig())
    captured: list[object] = []
    handle = c.inspect_async_nonblocking(
        messages=[{"role": "user", "content": "ping"}]
    )
    handle.on_complete(lambda r: captured.append(r))
    handle.result(timeout=5.0)
    # Callback dispatched synchronously on completion thread; wait briefly
    for _ in range(50):
        if captured:
            break
        time.sleep(0.01)
    assert captured, "on_complete callback should fire"
    c.close()


def test_inspect_async_nonblocking_zero_timeout_raises() -> None:
    c = Cerberus(CerberusConfig())
    handle = c.inspect_async_nonblocking(
        messages=[{"role": "user", "content": "hi"}]
    )
    # Usually the worker finishes immediately, but timeout=0 is defined
    # as "don't block". If the future has already resolved we get the
    # result; if not, we must get InspectionStillRunning.
    try:
        handle.result(timeout=0)
    except InspectionStillRunning:
        pass
    handle.result(timeout=5.0)
    c.close()


def test_inspect_async_nonblocking_safe_input_does_not_block() -> None:
    """Regression: nonblocking inspection on safe input must not return BLOCKED.

    The async-nonblocking path historically self-deadlocked on the
    single-worker executor when ``inspection_timeout_ms > 0`` — it
    submitted ``inspect`` (which itself submitted ``_inspect_core``) to
    the same pool, so the inner submission queued forever and every
    call returned a spurious ``INSPECTION_TIMEOUT`` block. The fix
    runs pre-flight checks inline and submits ``_inspect_core``
    directly, breaking the nesting.
    """
    c = Cerberus(CerberusConfig(inspection_timeout_ms=500))
    handle = c.inspect_async_nonblocking(
        messages=[{"role": "user", "content": "what's the weather like today?"}]
    )
    result = handle.result(timeout=5.0)
    assert not result.blocked, (
        f"safe input must not be blocked; got {result.events!r}"
    )
    c.close()


def test_top_level_observe_verifier_is_concrete_class() -> None:
    """Regression: ``from cerberus_ai import ObserveVerifier`` must
    bind to the concrete verifier class, not the abstract ``Verifier``
    Protocol.

    Earlier the top-level package re-exported with
    ``from .telemetry.observe import Verifier as ObserveVerifier``,
    which aliased the Protocol — calling ``ObserveVerifier(...)``
    raised ``TypeError`` because Protocols don't accept constructor
    args. The fix imports the concrete class.
    """
    import cerberus_ai
    from cerberus_ai.telemetry.observe import ObserveVerifier as ConcreteVerifier
    assert cerberus_ai.ObserveVerifier is ConcreteVerifier
    # Smoke: the public alias must be instantiable. We don't run a
    # real signing flow here — that's covered above.
    instance = cerberus_ai.ObserveVerifier(signing_key=b"\x00" * 32)
    assert callable(getattr(instance, "verify", None))
