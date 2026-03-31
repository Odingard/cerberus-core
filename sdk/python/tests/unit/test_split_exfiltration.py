"""Tests for the split exfiltration detector."""
from __future__ import annotations

from cerberus_ai.detectors.split_exfiltration import (
    OutboundCallRecord,
    SplitExfilSession,
    SplitExfiltrationSignal,
    detect_split_exfiltration,
)


def _make_session(
    records: list[OutboundCallRecord] | None = None,
    cumulative_bytes: int = 0,
) -> SplitExfilSession:
    session = SplitExfilSession()
    if records:
        session.outbound_records = records
    session.cumulative_bytes = cumulative_bytes
    return session


class TestDetectSplitExfiltration:
    def test_returns_none_for_non_outbound(self) -> None:
        result = detect_split_exfiltration(
            tool_name="read_db",
            tool_arguments={"query": "SELECT *"},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
            session=SplitExfilSession(),
        )
        assert result is None

    def test_returns_none_when_no_privileged_values(self) -> None:
        result = detect_split_exfiltration(
            tool_name="send_email",
            tool_arguments={"body": "x" * 5000},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=0,
            outbound_tools=["send_email"],
            session=SplitExfilSession(),
        )
        assert result is None

    def test_returns_none_below_threshold(self) -> None:
        session = _make_session(
            records=[
                OutboundCallRecord(tool_name="send_email", byte_size=100),
                OutboundCallRecord(tool_name="send_email", byte_size=100),
            ],
            cumulative_bytes=200,
        )
        result = detect_split_exfiltration(
            tool_name="send_email",
            tool_arguments={"body": "small"},
            turn_id="t-003",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
            session=session,
        )
        assert result is None

    def test_returns_none_with_insufficient_calls(self) -> None:
        # Only 1 prior call + current = 2, need 3
        session = _make_session(
            records=[
                OutboundCallRecord(tool_name="send_email", byte_size=6000),
            ],
            cumulative_bytes=6000,
        )
        result = detect_split_exfiltration(
            tool_name="send_email",
            tool_arguments={"body": "x" * 5000},
            turn_id="t-002",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
            session=session,
        )
        assert result is None

    def test_detects_volume_threshold_exceeded(self) -> None:
        session = _make_session(
            records=[
                OutboundCallRecord(tool_name="send_email", byte_size=4000),
                OutboundCallRecord(tool_name="send_email", byte_size=4000),
            ],
            cumulative_bytes=8000,
        )
        result = detect_split_exfiltration(
            tool_name="send_email",
            tool_arguments={"body": "x" * 3000},
            turn_id="t-003",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
            session=session,
        )
        assert result is not None
        assert isinstance(result, SplitExfiltrationSignal)
        assert result.signal == "SPLIT_EXFILTRATION"
        assert result.layer == "L3"
        assert result.outbound_call_count == 3
        assert result.cumulative_bytes > 10240

    def test_detects_sequential_pattern(self) -> None:
        session = _make_session(
            records=[
                OutboundCallRecord(
                    tool_name="send_data",
                    byte_size=100,
                    numeric_args=[1],
                ),
            ],
            cumulative_bytes=100,
        )
        result = detect_split_exfiltration(
            tool_name="send_data",
            tool_arguments={"body": "chunk", "page": 2},
            turn_id="t-002",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_data"],
            session=session,
        )
        assert result is not None
        assert result.sequential_pattern is True

    def test_custom_threshold(self) -> None:
        session = _make_session(
            records=[
                OutboundCallRecord(tool_name="send_email", byte_size=200),
                OutboundCallRecord(tool_name="send_email", byte_size=200),
            ],
            cumulative_bytes=400,
        )
        result = detect_split_exfiltration(
            tool_name="send_email",
            tool_arguments={"body": "x" * 200},
            turn_id="t-003",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
            session=session,
            threshold_bytes=500,
        )
        assert result is not None
        assert result.cumulative_bytes >= 500

    def test_session_state_updated(self) -> None:
        session = SplitExfilSession()
        detect_split_exfiltration(
            tool_name="send_email",
            tool_arguments={"body": "hello world"},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
            session=session,
        )
        assert len(session.outbound_records) == 1
        assert session.cumulative_bytes > 0

    def test_sequential_with_consistent_increment(self) -> None:
        session = _make_session(
            records=[
                OutboundCallRecord(
                    tool_name="export",
                    byte_size=50,
                    numeric_args=[0],
                ),
                OutboundCallRecord(
                    tool_name="export",
                    byte_size=50,
                    numeric_args=[100],
                ),
            ],
            cumulative_bytes=100,
        )
        result = detect_split_exfiltration(
            tool_name="export",
            tool_arguments={"data": "x", "offset": 200},
            turn_id="t-003",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["export"],
            session=session,
        )
        assert result is not None
        assert result.sequential_pattern is True

    def test_no_sequential_with_random_numbers(self) -> None:
        # 3 values with inconsistent increments: [3, 17, 22]
        # increments are 14, 5 -- not sequential
        session = _make_session(
            records=[
                OutboundCallRecord(
                    tool_name="export",
                    byte_size=50,
                    numeric_args=[3],
                ),
                OutboundCallRecord(
                    tool_name="export",
                    byte_size=50,
                    numeric_args=[17],
                ),
            ],
            cumulative_bytes=100,
        )
        result = detect_split_exfiltration(
            tool_name="export",
            tool_arguments={"data": "x", "offset": 22},
            turn_id="t-003",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["export"],
            session=session,
        )
        # No sequential pattern AND volume too low => None
        assert result is None

    def test_turn_id_and_timestamp_preserved(self) -> None:
        session = _make_session(
            records=[
                OutboundCallRecord(tool_name="send", byte_size=4000),
                OutboundCallRecord(tool_name="send", byte_size=4000),
            ],
            cumulative_bytes=8000,
        )
        result = detect_split_exfiltration(
            tool_name="send",
            tool_arguments={"body": "x" * 3000},
            turn_id="my-turn-99",
            timestamp=42000,
            privileged_values_count=2,
            outbound_tools=["send"],
            session=session,
        )
        assert result is not None
        assert result.turn_id == "my-turn-99"
        assert result.timestamp == 42000
