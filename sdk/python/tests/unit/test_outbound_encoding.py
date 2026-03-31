"""Tests for the outbound encoding detector."""
from __future__ import annotations

import base64

from cerberus_ai.detectors.outbound_encoding import (
    EncodedExfiltrationSignal,
    detect_outbound_encoding,
)


class TestDetectOutboundEncoding:
    def test_returns_none_for_non_outbound_tool(self) -> None:
        result = detect_outbound_encoding(
            tool_name="read_db",
            tool_arguments={"data": base64.b64encode(b"secret data here!!").decode()},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_when_no_privileged_values(self) -> None:
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={"data": base64.b64encode(b"secret data here!!").decode()},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=0,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_for_plain_text(self) -> None:
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={"to": "user@example.com", "body": "Hello world"},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_returns_none_for_empty_args(self) -> None:
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is None

    def test_detects_base64_in_outbound_args(self) -> None:
        encoded = base64.b64encode(b"SSN: 123-45-6789 credit card data").decode()
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={"body": encoded},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=2,
            outbound_tools=["send_email"],
        )
        assert result is not None
        assert isinstance(result, EncodedExfiltrationSignal)
        assert result.signal == "ENCODED_EXFILTRATION"
        assert result.layer == "L3"
        assert "base64" in result.encoding_types

    def test_detects_url_encoding_in_outbound(self) -> None:
        result = detect_outbound_encoding(
            tool_name="webhook_post",
            tool_arguments={
                "payload": "data%3Dpassword%3D%73%65%63%72%65%74%26user%3Dadmin"
            },
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["webhook_post"],
        )
        assert result is not None
        assert result.signal == "ENCODED_EXFILTRATION"
        assert "url_percent" in result.encoding_types

    def test_decoded_snippet_populated(self) -> None:
        encoded = base64.b64encode(b"Top secret document content here").decode()
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={"attachment": encoded},
            turn_id="t-001",
            timestamp=1500,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is not None
        assert result.decoded_snippet is not None
        assert len(result.decoded_snippet) > 0

    def test_turn_id_preserved(self) -> None:
        encoded = base64.b64encode(b"SSN 111-22-3333 exfiltrating now").decode()
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={"body": encoded},
            turn_id="my-turn-42",
            timestamp=9999,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is not None
        assert result.turn_id == "my-turn-42"
        assert result.timestamp == 9999

    def test_multiple_encoding_types(self) -> None:
        # Combine base64 and URL encoding in same payload
        b64_part = base64.b64encode(b"credential secret data payload").decode()
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={
                "body": f"{b64_part} and also %73%65%63%72%65%74"
            },
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is not None
        assert len(result.encoding_types) >= 1

    def test_signal_layer_is_l3(self) -> None:
        encoded = base64.b64encode(b"sensitive PII exfiltration data").decode()
        result = detect_outbound_encoding(
            tool_name="upload",
            tool_arguments={"data": encoded},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["upload"],
        )
        assert result is not None
        assert result.layer == "L3"

    def test_large_encoded_snippet_truncated(self) -> None:
        encoded = base64.b64encode(b"x" * 500).decode()
        result = detect_outbound_encoding(
            tool_name="send_email",
            tool_arguments={"data": encoded},
            turn_id="t-001",
            timestamp=1000,
            privileged_values_count=1,
            outbound_tools=["send_email"],
        )
        assert result is not None
        if result.decoded_snippet:
            assert len(result.decoded_snippet) <= 200
