"""Tests for cerberus_ai.egi.signer and signed EGI manifests."""
from __future__ import annotations

import pytest

from cerberus_ai.egi import (
    Ed25519Signer,
    Ed25519Verifier,
    EGIEngine,
    HmacSigner,
    MANIFEST_VERSION,
    Signer,
    Verifier,
    get_default_signer,
    reset_default_signer,
    set_default_signer,
)
from cerberus_ai.models import ToolCall, ToolSchema


# ── HmacSigner ──────────────────────────────────────────────────────


class TestHmacSigner:
    def test_round_trip(self) -> None:
        s = HmacSigner()
        sig = s.sign("payload")
        assert s.verify("payload", sig) is True

    def test_rejects_tampered_payload(self) -> None:
        s = HmacSigner()
        sig = s.sign("payload-a")
        assert s.verify("payload-b", sig) is False

    def test_rejects_tampered_signature(self) -> None:
        s = HmacSigner()
        sig = s.sign("payload")
        flipped = sig[:-2] + ("ff" if sig.endswith("00") else "00")
        assert s.verify("payload", flipped) is False

    def test_does_not_verify_across_keys(self) -> None:
        a = HmacSigner()
        b = HmacSigner()
        assert b.verify("payload", a.sign("payload")) is False

    def test_same_key_yields_same_key_id(self) -> None:
        key = b"\x00" * 32
        assert HmacSigner(key=key).key_id == HmacSigner(key=key).key_id

    def test_implements_protocols(self) -> None:
        s = HmacSigner()
        assert isinstance(s, Signer)
        assert isinstance(s, Verifier)


# ── Ed25519Signer / Ed25519Verifier ─────────────────────────────────


class TestEd25519Signer:
    def test_round_trip(self) -> None:
        s = Ed25519Signer()
        sig = s.sign("payload")
        assert s.verify("payload", sig) is True

    def test_rejects_tampered_payload(self) -> None:
        s = Ed25519Signer()
        sig = s.sign("payload-a")
        assert s.verify("payload-b", sig) is False

    def test_rejects_tampered_signature(self) -> None:
        s = Ed25519Signer()
        sig = s.sign("payload")
        flipped = sig[:-2] + ("ff" if sig.endswith("00") else "00")
        assert s.verify("payload", flipped) is False

    def test_does_not_verify_across_keypairs(self) -> None:
        a = Ed25519Signer()
        b = Ed25519Signer()
        assert b.verify("payload", a.sign("payload")) is False

    def test_verifier_only_path_via_pem(self) -> None:
        s = Ed25519Signer()
        pem = s.export_public_key_pem()
        v = Ed25519Verifier.from_pem(pem)
        assert v.key_id == s.key_id
        assert v.verify("payload", s.sign("payload")) is True

    def test_algorithm_and_key_id(self) -> None:
        s = Ed25519Signer()
        assert s.algorithm == "Ed25519"
        assert len(s.key_id) == 16

    def test_implements_protocols(self) -> None:
        s = Ed25519Signer()
        assert isinstance(s, Signer)
        assert isinstance(s, Verifier)


# ── default signer registry ─────────────────────────────────────────


class TestDefaultSignerRegistry:
    def setup_method(self) -> None:
        reset_default_signer()

    def test_returns_stable_default_signer(self) -> None:
        a = get_default_signer()
        b = get_default_signer()
        assert a is b
        assert a.algorithm == "Ed25519"

    def test_allows_host_app_override(self) -> None:
        injected = HmacSigner()
        set_default_signer(injected)
        assert get_default_signer() is injected

    def test_reset_recreates(self) -> None:
        a = get_default_signer()
        reset_default_signer()
        assert get_default_signer() is not a


# ── EGIEngine signed-manifest integration ───────────────────────────


def _tool(name: str, **flags: bool) -> ToolSchema:
    return ToolSchema(
        name=name,
        description=f"Description of {name}",
        parameters={"type": "object", "properties": {}},
        is_network_capable=flags.get("network", False),
        is_data_read=flags.get("read", False),
        is_data_write=flags.get("write", False),
    )


@pytest.fixture
def declared_tools() -> list[ToolSchema]:
    return [
        _tool("search", network=True, read=True),
        _tool("send_email", network=True, write=True),
    ]


class TestEGIEngineSignedManifest:
    def test_default_uses_ed25519(self, declared_tools: list[ToolSchema]) -> None:
        reset_default_signer()
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        assert engine.algorithm == "Ed25519"
        assert len(engine.key_id) == 16
        assert engine.verify_graph_integrity() is True

    def test_honours_injected_signer(self, declared_tools: list[ToolSchema]) -> None:
        hmac_signer = HmacSigner()
        engine = EGIEngine(
            "session-1",
            "agent-1",
            declared_tools,
            signer=hmac_signer,
        )
        assert engine.algorithm == "HMAC-SHA256"
        assert engine.key_id == hmac_signer.key_id
        assert engine.verify_graph_integrity() is True

    def test_legacy_signing_key_bytes_path(self, declared_tools: list[ToolSchema]) -> None:
        engine = EGIEngine(
            "session-1",
            "agent-1",
            declared_tools,
            signing_key=b"\x01" * 32,
        )
        assert engine.algorithm == "HMAC-SHA256"
        assert engine.verify_graph_integrity() is True

    def test_payload_covers_node_fields(self, declared_tools: list[ToolSchema]) -> None:
        """Mutating any node field must break verification."""
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        # Flip a capability bit on the first node
        engine._graph.nodes[0].is_network_capable = not engine._graph.nodes[0].is_network_capable
        assert engine.verify_graph_integrity() is False

    def test_payload_covers_schema_fingerprint(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        engine._graph.nodes[0].schema_fingerprint = "deadbeefdeadbeef"
        assert engine.verify_graph_integrity() is False

    def test_payload_covers_late_registrations(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        # Legitimate late registration re-signs → should still verify
        ok, _ = engine.register_tool_late(
            _tool("browse", network=True, read=True),
            reason="tool-use",
            authorized_by="tester",
            current_turn=1,
            l2_active=False,
        )
        assert ok is True
        assert engine.verify_graph_integrity() is True

        # Tamper with the ledger entry after re-sign
        engine._graph.late_registrations[0].authorized_by = "attacker"
        assert engine.verify_graph_integrity() is False

    def test_injection_assisted_registration_blocked(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        ok, msg = engine.register_tool_late(
            _tool("browse", network=True, read=True),
            reason="tool-use",
            authorized_by="tester",
            current_turn=1,
            l2_active=True,
        )
        assert ok is False
        assert "INJECTION_ASSISTED_REGISTRATION" in msg

    def test_blocked_registration_does_not_break_subsequent_verify(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        """A blocked (l2_active) registration appends to the signed ledger.
        The engine must re-sign so verify_graph_integrity does not report
        a spurious tampering failure on the next turn.
        """
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        ok, _ = engine.register_tool_late(
            _tool("browse", network=True, read=True),
            reason="tool-use",
            authorized_by="attacker",
            current_turn=1,
            l2_active=True,
        )
        assert ok is False
        assert engine.verify_graph_integrity() is True
        # The blocked record is in the signed ledger as evidence.
        assert any(
            r.l2_active_at_registration and r.tool_name == "browse"
            for r in engine.late_registrations
        )
        # A normal turn with no tool calls must still pass.
        assert engine.check_turn([], current_turn=2) == []

    def test_check_turn_detects_tampering(self, declared_tools: list[ToolSchema]) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        # Tamper — flip a capability bit
        engine._graph.nodes[0].is_network_capable = not engine._graph.nodes[0].is_network_capable
        violations = engine.check_turn([], current_turn=1)
        assert len(violations) == 1
        assert violations[0].violation_type == "GRAPH_INTEGRITY_FAILURE"

    def test_check_turn_unauthorized_tool(self, declared_tools: list[ToolSchema]) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        call = ToolCall(id="1", name="not_declared", arguments={})
        violations = engine.check_turn([call], current_turn=1)
        assert any(v.violation_type == "UNAUTHORIZED_TOOL_USE" for v in violations)

    def test_manifest_version_on_graph(self, declared_tools: list[ToolSchema]) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        assert engine._graph.manifest_version == MANIFEST_VERSION

    def test_cross_key_verification_fails(self, declared_tools: list[ToolSchema]) -> None:
        """A graph signed by one signer must not verify via a different signer's key."""
        a = Ed25519Signer()
        b = Ed25519Signer()
        engine = EGIEngine("session-1", "agent-1", declared_tools, signer=a)
        # Swap the verifier behind the engine — simulates an attacker
        # trying to verify against their own key.
        engine._verifier = b
        assert engine.verify_graph_integrity() is False


class TestStrictAmendment:
    def test_strict_without_signature_refuses(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        """In strict mode the runtime must refuse to self-re-sign."""
        engine = EGIEngine(
            "session-1",
            "agent-1",
            declared_tools,
            strict_amendment=True,
        )
        ok, msg = engine.register_tool_late(
            _tool("browse", network=True, read=True),
            reason="tool-use",
            authorized_by="tester",
            current_turn=1,
        )
        assert ok is False
        assert "STRICT_AMENDMENT_REQUIRED" in msg
        # Manifest must still verify under its original signature.
        assert engine.verify_graph_integrity() is True
        assert "browse" not in engine.registered_tools

    def test_strict_with_valid_signature_accepts(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        """Caller obtains a signature out-of-band, supplies it, engine accepts."""
        authority = Ed25519Signer()
        engine = EGIEngine(
            "session-1",
            "agent-1",
            declared_tools,
            signer=authority,
            strict_amendment=True,
        )
        tool = _tool("browse", network=True, read=True)
        payload = engine.preview_amendment_payload(
            tool, reason="tool-use", authorized_by="tester", current_turn=1
        )
        # Authority signs the preview — in production this round-trips
        # to a gateway / KMS; here we sign in-test.
        amendment_sig = authority.sign(payload)
        ok, msg = engine.register_tool_late(
            tool,
            reason="tool-use",
            authorized_by="tester",
            current_turn=1,
            amendment_signature=amendment_sig,
        )
        assert ok is True, msg
        assert "browse" in engine.registered_tools
        assert engine.verify_graph_integrity() is True

    def test_strict_rejects_forged_signature(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        """A signature from a different key must be rejected."""
        authority = Ed25519Signer()
        attacker = Ed25519Signer()
        engine = EGIEngine(
            "session-1",
            "agent-1",
            declared_tools,
            signer=authority,
            strict_amendment=True,
        )
        tool = _tool("browse", network=True, read=True)
        payload = engine.preview_amendment_payload(
            tool, reason="tool-use", authorized_by="tester", current_turn=1
        )
        forged = attacker.sign(payload)
        ok, msg = engine.register_tool_late(
            tool,
            reason="tool-use",
            authorized_by="tester",
            current_turn=1,
            amendment_signature=forged,
        )
        assert ok is False
        assert "STRICT_AMENDMENT_INVALID" in msg
        assert engine.verify_graph_integrity() is True
        assert "browse" not in engine.registered_tools

    def test_strict_blocked_l2_active_requires_signature(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        """Even blocked-L2 ledger entries need an authorized amendment in strict mode."""
        authority = Ed25519Signer()
        engine = EGIEngine(
            "session-1",
            "agent-1",
            declared_tools,
            signer=authority,
            strict_amendment=True,
        )
        tool = _tool("browse", network=True, read=True)
        payload = engine.preview_amendment_payload(
            tool,
            reason="tool-use",
            authorized_by="attacker",
            current_turn=1,
            l2_active=True,
        )
        amendment_sig = authority.sign(payload)
        ok, msg = engine.register_tool_late(
            tool,
            reason="tool-use",
            authorized_by="attacker",
            current_turn=1,
            l2_active=True,
            amendment_signature=amendment_sig,
        )
        assert ok is False  # L2-active is always a block
        assert "INJECTION_ASSISTED_REGISTRATION" in msg
        # Evidence lives in the signed ledger; subsequent verify must pass.
        assert engine.verify_graph_integrity() is True

    def test_preview_payload_is_non_mutating(
        self, declared_tools: list[ToolSchema]
    ) -> None:
        engine = EGIEngine("session-1", "agent-1", declared_tools)
        tools_before = list(engine.registered_tools)
        ledger_before = len(engine.late_registrations)
        _ = engine.preview_amendment_payload(
            _tool("browse", network=True, read=True),
            reason="tool-use",
            authorized_by="tester",
            current_turn=1,
        )
        assert engine.registered_tools == tools_before
        assert len(engine.late_registrations) == ledger_before
        assert engine.verify_graph_integrity() is True
