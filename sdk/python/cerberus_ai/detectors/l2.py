"""
cerberus_ai.detectors.l2
~~~~~~~~~~~~~~~~~~~~~~~~~
L2 — Untrusted Content Injection Detector.

Detects prompt injection attacks, jailbreaks, and instruction override attempts
present in the execution context from uncontrolled sources.

All detection is deterministic and rule-based.
"""
from __future__ import annotations

import re

from cerberus_ai.detectors.normalizer import normalize
from cerberus_ai.models import L2Detection, Message

# ── Injection pattern library ─────────────────────────────────────────────────

# Direct instruction override patterns
_OVERRIDE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("instruction_override", re.compile(
        r"\b(ignore|disregard|forget|override)\s+(all\s+)?(previous|prior|above|your)?\s*(instructions?|rules?|constraints?|guidelines?|prompts?|context)",
        re.I
    )),
    ("role_hijack", re.compile(
        r"\b(you\s+are\s+now|act\s+as|pretend\s+(to\s+be|you\s+are)|roleplay\s+as|your\s+new\s+(role|persona|identity)\s+is)",
        re.I
    )),
    ("system_prompt_reveal", re.compile(
        r"\b(reveal|show|print|output|repeat|display)\s+(your\s+)?(system\s+prompt|instructions?|initial\s+prompt|base\s+prompt|configuration)",
        re.I
    )),
    ("developer_mode", re.compile(
        r"\b(developer\s+mode|DAN\s+mode|jailbreak|uncensored\s+mode|unrestricted\s+mode|god\s+mode)",
        re.I
    )),
    ("exfil_instruction", re.compile(
        r"\b(send|transmit|upload|post|email|write)\s+.{0,50}\b(to\s+)?(http|https|ftp|smtp|my\s+server|external)",
        re.I
    )),
    ("context_injection_marker", re.compile(
        r"(</?(system|human|assistant|user|instruction|prompt|context)>|\[\s*(system|inst|instruction)\s*\])",
        re.I
    )),
    ("delimiter_injection", re.compile(
        r"(#{3,}|={3,}|\*{3,}|-{3,})\s*(new\s+(instruction|prompt|task)|end\s+of\s+(document|context|text))",
        re.I
    )),
    ("tool_invocation_injection", re.compile(
        r"(call\s+(the\s+)?(function|tool|api)|invoke|execute)\s+['\"]?\w+['\"]?\s*(with|using)?",
        re.I
    )),
    ("data_leakage_instruction", re.compile(
        r"\b(leak|exfiltrate|steal|extract|dump|export)\s+(the\s+)?(data|information|context|memory|conversation|secrets?|keys?|tokens?)",
        re.I
    )),
    ("indirect_injection_marker", re.compile(
        r"(\[INJECT\]|\[PAYLOAD\]|\[ATTACK\]|<inject>|<!-- inject)",
        re.I
    )),
    ("data_leakage_verb_destination", re.compile(
        r"\b(exfiltrate|leak|steal|dump|extract|export|send|transmit|email|upload)\b"
        r".{0,80}\b(to|at|via)\b.{0,60}\b(attacker|evil|malicious|external|http|https|ftp|smtp|@)",
        re.I | re.S
    )),
    ("exfiltrate_standalone", re.compile(
        r"\b(exfiltrate|steal|leak)\s+(all|the|every)?\s*(data|records?|information|files?|credentials?|secrets?|keys?)",
        re.I
    )),
    ("send_to_external", re.compile(
        r"\b(send|email|transmit|upload|post)\b.{0,60}"
        r"(attacker|evil\.|malicious|exfil|@evil|@attacker)",
        re.I | re.S
    )),
]

# Suspicious structural patterns in untrusted content (tool results, user messages)
_STRUCTURAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("hidden_text", re.compile(
        r"(color:\s*white|display:\s*none|opacity:\s*0|font-size:\s*0)",
        re.I,
    )),
    ("unicode_rtl", re.compile(r"[\u202A-\u202E\u2066-\u2069]")),   # RTL/LTR override chars
    ("null_byte", re.compile(r"\x00")),
    ("prompt_boundary_spoof", re.compile(
        r"Human:|Assistant:|System:"
        r"|<\|im_start\|>|<\|im_end\|>"
        r"|\[INST\]|\[/INST\]"
    )),
]

# Untrusted message roles — content from these roles should be treated as potentially adversarial
_UNTRUSTED_ROLES = {"user", "tool"}
_HIGH_RISK_ROLES = {"tool"}   # tool results from external sources are highest risk


class L2Detector:
    """
    Detects L2 — Untrusted Content Injection.

    Checks:
      1. All injection patterns against normalized content
      2. Structural/encoding manipulation patterns
      3. Source context — tool results and user messages are untrusted
    """

    def detect(self, messages: list[Message]) -> L2Detection:
        injection_patterns: list[str] = []
        evidence: list[str] = []
        confidence = 0.0
        encoding_detected: str | None = None

        for msg in messages:
            content_raw = msg.content if isinstance(msg.content, str) else str(msg.content or "")
            if not content_raw.strip():
                continue

            # Normalize — decode encoding obfuscation before pattern matching
            norm = normalize(content_raw)
            content = norm.text
            if norm.was_encoded:
                encoding_detected = ",".join(norm.encodings_found)
                evidence.append(
                    f"Encoding obfuscation detected in"
                    f" {msg.role} message:"
                    f" {encoding_detected}"
                )
                confidence = max(confidence, 0.60)

            # Score by message role
            role_multiplier = 1.0
            if msg.role in _HIGH_RISK_ROLES:
                role_multiplier = 1.2           # tool results get extra scrutiny
            elif msg.role not in _UNTRUSTED_ROLES:
                role_multiplier = 0.5           # system/assistant messages are less suspect

            # Check override patterns
            for name, pattern in _OVERRIDE_PATTERNS:
                m = pattern.search(content)
                if m:
                    injection_patterns.append(name)
                    evidence.append(
                        f"Injection pattern '{name}'"
                        f" in {msg.role}:"
                        f" '{m.group(0)[:80]}'"
                    )
                    base_conf = 0.85 if msg.role in _UNTRUSTED_ROLES else 0.50
                    confidence = max(confidence, min(base_conf * role_multiplier, 1.0))

            # Check structural patterns
            for name, pattern in _STRUCTURAL_PATTERNS:
                m = pattern.search(content_raw)  # structural checks on raw, not normalized
                if m:
                    injection_patterns.append(f"structural:{name}")
                    evidence.append(f"Structural injection indicator '{name}' in {msg.role}")
                    confidence = max(confidence, 0.75)

        return L2Detection(
            injection_patterns=list(set(injection_patterns)),
            evidence=evidence,
            confidence=confidence,
            encoding_detected=encoding_detected,
        )
