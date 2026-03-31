"""Tests for the tool chain (multi-hop exfiltration) detector."""
from __future__ import annotations

from cerberus_ai.detectors.tool_chain import (
    MultiHopSignal,
    ToolChainEntry,
    classify_tool_role,
    detect_tool_chain_exfiltration,
)


def _entry(name: str, turn: str = "t-001") -> ToolChainEntry:
    return ToolChainEntry(tool_name=name, turn_id=turn)


class TestClassifyToolRole:
    def test_explicit_outbound_takes_priority(self) -> None:
        assert classify_tool_role("my_tool", ["my_tool"]) == "outbound"

    def test_outbound_pattern_send(self) -> None:
        assert classify_tool_role("send_email", []) == "outbound"

    def test_outbound_pattern_upload(self) -> None:
        assert classify_tool_role("upload_file", []) == "outbound"

    def test_transform_pattern_encode(self) -> None:
        assert classify_tool_role("encodePayload", []) == "transform"

    def test_transform_before_read(self) -> None:
        # "encodePayload" contains "load" (a read pattern) but transform wins
        assert classify_tool_role("encodePayload", []) == "transform"

    def test_read_pattern_query(self) -> None:
        assert classify_tool_role("query_database", []) == "read"

    def test_read_pattern_fetch(self) -> None:
        assert classify_tool_role("fetchRecords", []) == "read"

    def test_unknown_tool(self) -> None:
        assert classify_tool_role("do_nothing", []) == "unknown"


class TestDetectToolChainExfiltration:
    def test_returns_none_when_not_outbound(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="query_db",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("read_db"), _entry("format_data")],
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_when_no_privileged_values(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="send_email",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("read_db"), _entry("format_data")],
            privileged_values_count=0,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_when_history_too_short(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="send_email",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("read_db")],
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_without_transform(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="send_email",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("read_db"), _entry("read_more")],
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_without_read(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="send_email",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("format_data"), _entry("compress_data")],
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_detects_read_transform_send_chain(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="send_email",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("query_db"), _entry("format_data")],
            privileged_values_count=3,
            outbound_tools=["send_email"],
        )
        assert result is not None
        assert isinstance(result, MultiHopSignal)
        assert result.signal == "MULTI_HOP_EXFILTRATION"
        assert result.layer == "L3"
        assert result.chain_length == 3
        assert "query_db" in result.chain_tools
        assert "format_data" in result.chain_tools
        assert "send_email" in result.chain_tools

    def test_detects_chain_with_multiple_transforms(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="upload_file",
            turn_id="t-005",
            timestamp=2000,
            tool_call_history=[
                _entry("fetch_records"),
                _entry("parse_json"),
                _entry("encode_base64"),
                _entry("compress_data"),
            ],
            privileged_values_count=1,
            outbound_tools=["upload_file"],
        )
        assert result is not None
        assert result.chain_length == 5

    def test_detects_outbound_via_pattern_not_explicit(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="submit_form",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("read_file"), _entry("transform_payload")],
            privileged_values_count=1,
            outbound_tools=[],  # no explicit, but "submit" matches pattern
        )
        assert result is not None
        assert result.signal == "MULTI_HOP_EXFILTRATION"

    def test_chain_tools_in_correct_order(self) -> None:
        result = detect_tool_chain_exfiltration(
            tool_name="send_email",
            turn_id="t-003",
            timestamp=1000,
            tool_call_history=[_entry("query_db"), _entry("format_csv")],
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is not None
        assert result.chain_tools == ["query_db", "format_csv", "send_email"]
