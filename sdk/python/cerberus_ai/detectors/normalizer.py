"""
cerberus_ai.detectors.normalizer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
6-pass multi-encoding normalization pipeline.
Runs on complete turn buffers before inspection to prevent split-encoding evasion.

Passes (in order):
  1. Base64 decode
  2. Unicode escape decode (\\uXXXX, \\UXXXXXXXX)
  3. HTML entity decode (&amp; &#x...; &#...;)
  4. URL percent-decode (%XX)
  5. Zero-width character strip
  6. Homoglyph normalization (Unicode → ASCII equivalents)
"""
from __future__ import annotations

import base64
import html
import logging
import re
import unicodedata
import urllib.parse

# ── Homoglyph mapping (high-value subset) ─────────────────────────────────────
_HOMOGLYPHS: dict[str, str] = {
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "r",
    "\u0441": "c", "\u0443": "u", "\u0445": "x", "\u0456": "i",
    "\u04CF": "l", "\u1D00": "a", "\u1D04": "c", "\u1D07": "e",
    "\u1D0A": "j", "\u1D0B": "k", "\u1D0D": "m", "\u1D0F": "o",
    "\u1D18": "p", "\u1D1B": "t", "\u1D1C": "u", "\u1D20": "v",
    "\u1D21": "w", "\u1D22": "z",
    "\u2010": "-", "\u2011": "-", "\u2012": "-", "\u2013": "-",
    "\u2014": "-", "\u2015": "-",
    "\u2018": "'", "\u2019": "'", "\u201A": "'",
    "\u201C": '"', "\u201D": '"', "\u201E": '"',
    "\uFF01": "!", "\uFF02": '"', "\uFF03": "#", "\uFF04": "$",
    "\uFF05": "%", "\uFF06": "&", "\uFF07": "'", "\uFF08": "(",
    "\uFF09": ")", "\uFF0A": "*", "\uFF0B": "+", "\uFF0C": ",",
    "\uFF0D": "-", "\uFF0E": ".", "\uFF0F": "/",
    "\uFF10": "0", "\uFF11": "1", "\uFF12": "2", "\uFF13": "3",
    "\uFF14": "4", "\uFF15": "5", "\uFF16": "6", "\uFF17": "7",
    "\uFF18": "8", "\uFF19": "9",
    "\uFF1A": ":", "\uFF1B": ";", "\uFF1C": "<", "\uFF1D": "=",
    "\uFF1E": ">", "\uFF1F": "?", "\uFF20": "@",
}

# Zero-width and invisible characters to strip
_ZERO_WIDTH = re.compile(
    r"[\u200B\u200C\u200D\u200E\u200F\u2028\u2029\uFEFF\u00AD\u034F\u115F\u1160\u17B4\u17B5\u3164\uFFA0]"
)

# Base64 segment detector (min 16 chars to reduce false positives)
_B64_SEGMENT = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/])")

# Unicode escape patterns
_UNICODE_ESCAPE = re.compile(r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")

# HTML entities
_HTML_NUMERIC = re.compile(r"&#x([0-9a-fA-F]+);|&#([0-9]+);")


def _decode_base64_segments(text: str) -> tuple[str, bool]:
    """Attempt to decode base64 segments within text. Returns (decoded_text, found)."""
    found = False
    def replacer(m: re.Match) -> str:  # type: ignore[type-arg]
        nonlocal found
        try:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="ignore")
            if decoded.isprintable() or "\n" in decoded:
                found = True
                return decoded
        except Exception:
            logging.debug("Failed to decode base64 segment", exc_info=True)
        return str(m.group(0))
    return _B64_SEGMENT.sub(replacer, text), found


def _decode_unicode_escapes(text: str) -> str:
    """Decode \\uXXXX and \\UXXXXXXXX sequences."""
    def replacer(m: re.Match) -> str:  # type: ignore[type-arg]
        hex4, hex8 = m.group(1), m.group(2)
        try:
            if hex4:
                return chr(int(hex4, 16))
            if hex8:
                return chr(int(hex8, 16))
        except (ValueError, OverflowError):
            pass
        return str(m.group(0))
    return _UNICODE_ESCAPE.sub(replacer, text)


def _decode_html_entities(text: str) -> str:
    """Decode HTML named and numeric entities."""
    # Named entities via stdlib
    result = html.unescape(text)
    # Numeric entities not caught by html.unescape
    def replacer(m: re.Match) -> str:  # type: ignore[type-arg]
        hex_val, dec_val = m.group(1), m.group(2)
        try:
            code = int(hex_val, 16) if hex_val else int(dec_val)
            return chr(code)
        except (ValueError, OverflowError):
            return str(m.group(0))
    return _HTML_NUMERIC.sub(replacer, result)


def _decode_url_percent(text: str) -> str:
    """URL percent-decode %XX sequences."""
    try:
        return urllib.parse.unquote(text, errors="ignore")
    except Exception:
        return text


def _strip_zero_width(text: str) -> str:
    """Remove zero-width and invisible characters."""
    return _ZERO_WIDTH.sub("", text)


def _normalize_homoglyphs(text: str) -> str:
    """Map Unicode homoglyphs to ASCII equivalents."""
    # First NFKC normalize (handles many lookalikes)
    text = unicodedata.normalize("NFKC", text)
    # Then apply our homoglyph table
    return "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)


class NormalizationResult:
    __slots__ = ("text", "encodings_found", "original")

    def __init__(self, text: str, encodings_found: list[str], original: str) -> None:
        self.text = text
        self.encodings_found = encodings_found
        self.original = original

    @property
    def was_encoded(self) -> bool:
        return bool(self.encodings_found)


def normalize(text: str) -> NormalizationResult:
    """
    Run the full 6-pass normalization pipeline on a text buffer.
    Returns the normalized text and a list of encodings found.
    """
    original = text
    encodings_found: list[str] = []

    # Pass 1 — Base64
    decoded, found = _decode_base64_segments(text)
    if found:
        encodings_found.append("base64")
        text = decoded

    # Pass 2 — Unicode escapes
    decoded2 = _decode_unicode_escapes(text)
    if decoded2 != text:
        encodings_found.append("unicode_escape")
        text = decoded2

    # Pass 3 — HTML entities
    decoded3 = _decode_html_entities(text)
    if decoded3 != text:
        encodings_found.append("html_entity")
        text = decoded3

    # Pass 4 — URL percent-decode
    decoded4 = _decode_url_percent(text)
    if decoded4 != text:
        encodings_found.append("url_percent")
        text = decoded4

    # Pass 5 — Zero-width strip
    decoded5 = _strip_zero_width(text)
    if decoded5 != text:
        encodings_found.append("zero_width")
        text = decoded5

    # Pass 6 — Homoglyph normalization
    decoded6 = _normalize_homoglyphs(text)
    if decoded6 != text:
        encodings_found.append("homoglyph")
        text = decoded6

    return NormalizationResult(text=text, encodings_found=encodings_found, original=original)
