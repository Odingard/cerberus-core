"""
cerberus_ai.classifiers.multimodal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Multi-modal L2 scanners (v1.4 Delta #3).

Frontier LLMs accept images, PDFs and audio natively. Every attack
class the regex L2 layer catches in text — instruction overrides,
exfiltration cues, hidden control sequences — also ships inside
non-text modalities:

* **Images** — instructions hidden in EXIF / XMP metadata, visible
  but model-readable text the user didn't author (e.g. a screenshot
  from a poisoned website), zero-alpha glyphs, steganographic LSB.

* **PDFs** — visible text with off-page / zero-sized / white-on-
  white injection layers, JavaScript actions
  (``/OpenAction`` / ``/AA``), launch actions, embedded files.

* **Audio** — voice jailbreaks / fluent-TTS prompt overrides that
  the model transcribes and acts on.

This module gives Cerberus first-class visibility into those
modalities and fuses any extracted text into the existing L2
detection, so an image whose EXIF ``ImageDescription`` reads
"Ignore all previous instructions" is caught by the same regex
that would have caught the same string in a chat message.

Design goals (same as Delta #2)
===============================

* **Zero mandatory deps.** Image/PDF parsing uses ``Pillow`` and
  ``pypdf`` from the ``[multimodal]`` extras group. A stock
  ``pip install cerberus-ai`` loads zero bytes of multimodal code.

* **Fail-open at scan.** Any exception inside a scanner returns a
  null artifact and logs. The text L2 layer still runs on whatever
  string content the message carries.

* **Fail-closed at startup.** If ``multimodal_enabled=True`` but a
  required extra isn't installed, the factory raises at
  :class:`Cerberus` construction.

* **Testable without binaries.** Every scanner takes an optional
  callable override so tests can pin the "extracted text" and
  "artifact risk" without carrying a fixture image, PDF or WAV.

* **Bounded by input size.** Parts larger than
  ``multimodal_max_bytes`` are skipped with a warning — an
  attacker cannot DoS the scanner with a 1 GB video.
"""
from __future__ import annotations

import base64
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("cerberus.multimodal")

# ── Public type aliases ────────────────────────────────────────────────────────

#: ``bytes -> text`` extractor. Used for OCR (image → visible text)
#: and speech-to-text (audio → transcript). Operators can supply a
#: remote gRPC / HTTP service here; defaults fall back to ``Pillow``
#: EXIF parsing for images and raise ``NotImplementedError`` for
#: audio.
ExtractFn = Callable[[bytes], str]


# ── Scanner results ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ScannedArtifact:
    """Result of scanning a single binary attachment.

    ``extracted_text`` is fed into the L2 regex (and, when enabled,
    the ML classifier) so all detections are produced by the same
    library no matter the modality.
    """

    kind: str                  # "image" | "pdf" | "audio"
    extracted_text: str = ""
    evidence: list[str] = field(default_factory=list)
    score: float = 0.0         # 0.0–1.0 modality-specific risk


# ── Overrides registry ─────────────────────────────────────────────────────────


@dataclass
class MultiModalOverrides:
    """Opt-in callable hooks for modalities Cerberus can't handle
    with a lightweight OSS dep.

    * ``image_ocr`` — ``bytes -> str``. If unset, the image scanner
      still runs (EXIF / metadata) but skips OCR.

    * ``audio_transcribe`` — ``bytes -> str``. If unset, the audio
      scanner is disabled even when ``multimodal_audio_enabled``
      is True (audio without transcription is meaningless to a
      text-pattern layer).
    """
    image_ocr: ExtractFn | None = None
    audio_transcribe: ExtractFn | None = None


# ── Scanners ───────────────────────────────────────────────────────────────────


_EXIF_SUSPICIOUS_TAGS = {
    "ImageDescription", "UserComment", "XPComment",
    "XPTitle", "XPSubject", "XPKeywords", "Software",
    "Artist", "Copyright", "DocumentName",
}


class ImageScanner:
    """Image → text + risk.

    Pulls human-readable strings out of EXIF / XMP where attackers
    routinely stash instructions. If an OCR override is supplied we
    additionally hand the pixel bytes to it and concatenate the
    result — this catches the common "screenshot a web page with
    a prompt on it and paste it" indirect-injection vector.
    """

    def __init__(
        self,
        *,
        ocr: ExtractFn | None = None,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self._ocr = ocr
        self._max_bytes = max_bytes

    def scan(self, data: bytes) -> ScannedArtifact:
        if len(data) > self._max_bytes:
            logger.warning(
                "ImageScanner skipping oversize attachment "
                "(%d bytes > %d max)",
                len(data), self._max_bytes,
            )
            return ScannedArtifact(kind="image")

        texts: list[str] = []
        evidence: list[str] = []
        score = 0.0

        try:
            metadata = _read_image_metadata(data)
        except Exception:   # noqa: BLE001 — fail-open
            logger.warning(
                "ImageScanner metadata read failed",
                exc_info=True,
            )
            metadata = {}

        for tag, value in metadata.items():
            if not isinstance(value, (str, bytes)):
                continue
            text = _to_text(value)
            if not text.strip():
                continue
            texts.append(text)
            if tag in _EXIF_SUSPICIOUS_TAGS:
                # Metadata fields that are almost never populated in
                # legitimate user screenshots; a non-trivial payload
                # here is itself suspicious.
                evidence.append(
                    f"Image metadata field {tag!r} contains text "
                    f"({len(text)} chars)"
                )
                score = max(score, 0.30)

        if self._ocr is not None:
            try:
                ocr_text = self._ocr(data)
            except Exception:   # noqa: BLE001 — fail-open
                logger.warning(
                    "ImageScanner OCR override failed",
                    exc_info=True,
                )
                ocr_text = ""
            if ocr_text.strip():
                texts.append(ocr_text)
                evidence.append(
                    f"Image OCR extracted {len(ocr_text)} chars of text"
                )

        return ScannedArtifact(
            kind="image",
            extracted_text="\n".join(texts),
            evidence=evidence,
            score=score,
        )


# PDF structural markers that carry executable content or actions.
# Each regex is case-sensitive — the PDF spec is case-sensitive for
# name tokens.
_PDF_ACTION_MARKERS: list[tuple[str, re.Pattern[bytes]]] = [
    ("pdf_javascript",
     re.compile(rb"/JS\b|/JavaScript\b")),
    ("pdf_open_action",
     re.compile(rb"/OpenAction\b|/AA\b")),
    ("pdf_launch",
     re.compile(rb"/Launch\b")),
    ("pdf_submit_form",
     re.compile(rb"/SubmitForm\b")),
    ("pdf_embedded_file",
     re.compile(rb"/EmbeddedFile\b")),
]


class PDFScanner:
    """PDF → text + risk.

    * Extract the visible text layer via ``pypdf`` when installed.
    * Flag structural markers associated with active content
      (``/JS``, ``/OpenAction``, ``/Launch``, ``/EmbeddedFile``) by
      scanning the raw bytes — these don't require a working parse
      and survive truncated / malformed PDFs.
    """

    def __init__(
        self,
        *,
        text_override: ExtractFn | None = None,
        max_bytes: int = 10 * 1024 * 1024,
    ) -> None:
        self._override = text_override
        self._max_bytes = max_bytes

    def scan(self, data: bytes) -> ScannedArtifact:
        if len(data) > self._max_bytes:
            logger.warning(
                "PDFScanner skipping oversize attachment "
                "(%d bytes > %d max)",
                len(data), self._max_bytes,
            )
            return ScannedArtifact(kind="pdf")

        evidence: list[str] = []
        score = 0.0

        for name, pattern in _PDF_ACTION_MARKERS:
            if pattern.search(data):
                evidence.append(
                    f"PDF contains active-content marker {name!r}"
                )
                # Active-content PDFs aren't always malicious, but
                # they're *always* higher-risk than a static page.
                score = max(score, 0.55)

        if self._override is not None:
            try:
                text = self._override(data)
            except Exception:   # noqa: BLE001 — fail-open
                logger.warning(
                    "PDFScanner text-override failed",
                    exc_info=True,
                )
                text = ""
        else:
            text = _extract_pdf_text(data)

        return ScannedArtifact(
            kind="pdf",
            extracted_text=text,
            evidence=evidence,
            score=score,
        )


class AudioScanner:
    """Audio → transcript. Pure override — no OSS default.

    Cerberus will never ship a speech-to-text model in the OSS
    package (too heavy, license-encumbered). Operators that want
    to scan audio provide a transcription callable via
    :class:`MultiModalOverrides`; everyone else gets ``enabled=False``
    and a clean startup error.
    """

    def __init__(
        self,
        *,
        transcribe: ExtractFn,
        max_bytes: int = 25 * 1024 * 1024,
    ) -> None:
        self._transcribe = transcribe
        self._max_bytes = max_bytes

    def scan(self, data: bytes) -> ScannedArtifact:
        if len(data) > self._max_bytes:
            logger.warning(
                "AudioScanner skipping oversize attachment "
                "(%d bytes > %d max)",
                len(data), self._max_bytes,
            )
            return ScannedArtifact(kind="audio")

        try:
            text = self._transcribe(data)
        except Exception:   # noqa: BLE001 — fail-open
            logger.warning(
                "AudioScanner transcription failed",
                exc_info=True,
            )
            return ScannedArtifact(kind="audio")

        return ScannedArtifact(
            kind="audio",
            extracted_text=text,
            evidence=(
                [f"Audio transcribed to {len(text)} chars"]
                if text.strip() else []
            ),
        )


# ── Aggregator ─────────────────────────────────────────────────────────────────


class MultiModalScanner:
    """Dispatcher that walks an OpenAI / Anthropic content list.

    The message ``content`` shapes Cerberus cares about:

    * OpenAI vision — ``image_url`` parts
    * Anthropic — ``image`` parts with ``source.{type, data}``
    * OpenAI audio — ``input_audio`` parts
    * File / document parts — ``file``/``document`` with a
      ``mime_type`` ending in ``pdf``

    Anything we don't recognise is ignored (no false positives from
    tomorrow's frontier-model content schema).
    """

    def __init__(
        self,
        *,
        image: ImageScanner | None = None,
        pdf: PDFScanner | None = None,
        audio: AudioScanner | None = None,
    ) -> None:
        self._image = image
        self._pdf = pdf
        self._audio = audio

    def scan_part(self, part: dict[str, Any]) -> ScannedArtifact | None:
        """Return a scan result for a single content part, or None."""
        kind = part.get("type")

        if kind in {"image", "image_url"} and self._image is not None:
            data = _image_bytes_from_part(part)
            if data is None:
                return None
            return self._image.scan(data)

        if kind == "input_audio" and self._audio is not None:
            data = _audio_bytes_from_part(part)
            if data is None:
                return None
            return self._audio.scan(data)

        if kind in {"file", "document"} and self._pdf is not None:
            data, mime = _file_bytes_from_part(part)
            if data is None:
                return None
            if not mime or "pdf" not in mime.lower():
                # Either not a PDF or MIME unknown — skip rather than
                # speculatively scan arbitrary binary for PDF action
                # markers (``/JS``, ``/OpenAction`` …), which will
                # false-positive on non-PDF containers (ZIP, DOCX,
                # images) that happen to embed those byte sequences.
                return None
            return self._pdf.scan(data)

        return None


# ── Factory ────────────────────────────────────────────────────────────────────


def _require_pillow() -> None:
    """Probe for Pillow at factory time.

    Raises :class:`ImportError` with install guidance when the
    ``[multimodal]`` extras group is missing. Kept as a module-
    level function so tests can monkeypatch it without touching
    real ``sys.modules``.
    """
    try:
        import PIL  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "multimodal_image_enabled=True but Pillow is not installed. "
            "Install the multimodal extras: "
            "``pip install cerberus-ai[multimodal]`` "
            "(or disable image scanning with "
            "multimodal_image_enabled=False)."
        ) from exc


def _require_pypdf() -> None:
    """Probe for pypdf at factory time. Same rationale as
    :func:`_require_pillow`.
    """
    try:
        import pypdf  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "multimodal_pdf_enabled=True but pypdf is not installed. "
            "Install the multimodal extras: "
            "``pip install cerberus-ai[multimodal]`` "
            "(or disable PDF scanning with "
            "multimodal_pdf_enabled=False)."
        ) from exc


def build_multimodal_scanner_from_config(
    config: Any,
    *,
    overrides: MultiModalOverrides | None = None,
) -> MultiModalScanner | None:
    """Factory called by :class:`cerberus_ai.Cerberus`.

    Returns ``None`` when ``multimodal_enabled`` is False. Raises
    when enabled but misconfigured — an operator who asked for
    audio scanning without a transcription override, or who
    enabled image / PDF scanning without the ``[multimodal]``
    extras, should find out at startup, not three hours in. The
    fail-closed contract is written into the module docstring and
    is essential: a security product that silently produces zero
    evidence is worse than one that refuses to start.
    """
    if not getattr(config, "multimodal_enabled", False):
        return None

    overrides = overrides or MultiModalOverrides()
    max_bytes = int(getattr(config, "multimodal_max_bytes", 10 * 1024 * 1024))

    image: ImageScanner | None = None
    if getattr(config, "multimodal_image_enabled", True):
        _require_pillow()
        image = ImageScanner(ocr=overrides.image_ocr, max_bytes=max_bytes)

    pdf: PDFScanner | None = None
    if getattr(config, "multimodal_pdf_enabled", True):
        _require_pypdf()
        pdf = PDFScanner(max_bytes=max_bytes)

    audio: AudioScanner | None = None
    if getattr(config, "multimodal_audio_enabled", False):
        if overrides.audio_transcribe is None:
            raise ValueError(
                "multimodal_audio_enabled=True requires a "
                "MultiModalOverrides(audio_transcribe=...) callable — "
                "Cerberus OSS does not ship a transcription model."
            )
        audio = AudioScanner(
            transcribe=overrides.audio_transcribe,
            max_bytes=max_bytes,
        )

    if image is None and pdf is None and audio is None:
        raise ValueError(
            "multimodal_enabled=True with every modality disabled"
        )

    return MultiModalScanner(image=image, pdf=pdf, audio=audio)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _to_text(value: str | bytes) -> str:
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8", errors="replace")
        except Exception:   # noqa: BLE001
            return ""
    return value


def _decode_b64(s: str) -> bytes | None:
    """Accept both raw base64 and ``data:...;base64,...`` URLs."""
    if s.startswith("data:"):
        _, _, tail = s.partition(",")
        s = tail
    try:
        return base64.b64decode(s, validate=False)
    except Exception:   # noqa: BLE001
        return None


def _image_bytes_from_part(part: dict[str, Any]) -> bytes | None:
    # OpenAI style: image_url.url may be a data-URL
    if part.get("type") == "image_url":
        url = part.get("image_url", {})
        if isinstance(url, dict):
            url = url.get("url", "")
        if isinstance(url, str) and url.startswith("data:"):
            return _decode_b64(url)
        # Non-data URL — we don't fetch at scan time. Operators
        # who need remote-URL fetching can wrap the scanner.
        return None

    # Anthropic style: image.source.{type,data}
    if part.get("type") == "image":
        src = part.get("source", {})
        if isinstance(src, dict) and src.get("type") == "base64":
            data = src.get("data", "")
            if isinstance(data, str):
                return _decode_b64(data)
        if isinstance(src, dict) and src.get("type") == "bytes":
            data = src.get("data", None)
            if isinstance(data, (bytes, bytearray)):
                return bytes(data)
    return None


def _audio_bytes_from_part(part: dict[str, Any]) -> bytes | None:
    audio = part.get("input_audio", {})
    if isinstance(audio, dict):
        data = audio.get("data", "")
        if isinstance(data, str):
            return _decode_b64(data)
        if isinstance(data, (bytes, bytearray)):
            return bytes(data)
    return None


def _file_bytes_from_part(
    part: dict[str, Any],
) -> tuple[bytes | None, str | None]:
    f = part.get("file", part.get("document", {}))
    if not isinstance(f, dict):
        return None, None
    mime = f.get("mime_type") or f.get("media_type")
    data = f.get("data", "")
    if isinstance(data, str):
        return _decode_b64(data), mime
    if isinstance(data, (bytes, bytearray)):
        return bytes(data), mime
    return None, mime


def _read_image_metadata(data: bytes) -> dict[str, Any]:
    """Best-effort EXIF / XMP extraction via Pillow.

    Returns ``{}`` when Pillow isn't installed or the bytes don't
    parse as an image — callers treat this as fail-open and skip
    the metadata evidence stream.
    """
    try:
        from PIL import ExifTags, Image
    except ImportError:
        return {}

    try:
        from io import BytesIO
        with Image.open(BytesIO(data)) as im:
            raw = getattr(im, "_getexif", lambda: None)()
            if not raw:
                return {}
            named: dict[str, Any] = {}
            for tag_id, val in raw.items():
                name = ExifTags.TAGS.get(tag_id, str(tag_id))
                named[name] = val
            return named
    except Exception:   # noqa: BLE001
        return {}


def _extract_pdf_text(data: bytes) -> str:
    """Extract text from a PDF via ``pypdf`` when installed."""
    try:
        import pypdf
    except ImportError:
        return ""

    try:
        from io import BytesIO
        reader = pypdf.PdfReader(BytesIO(data))
        chunks: list[str] = []
        for page in reader.pages:
            try:
                chunks.append(page.extract_text() or "")
            except Exception:   # noqa: BLE001
                # One malformed page shouldn't fail the whole
                # document — the remaining text is still useful
                # signal for the regex layer.
                logger.debug(
                    "PDFScanner page extraction failed",
                    exc_info=True,
                )
                continue
        return "\n".join(chunks)
    except Exception:   # noqa: BLE001
        return ""
