"""
cerberus_ai.classifiers.ml_injection
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

ML-backed prompt-injection classifier (v1.4 Delta #2).

The L2 regex library (:mod:`cerberus_ai.detectors.l2`) is precise but
pattern-bound: it cannot see semantically-clean but behaviourally-
hostile injection (adversarial suffixes from GCG/AutoDAN/PAIR, fluent
natural-language override instructions embedded in RAG documents,
translated jailbreaks, ...). This module adds a small ONNX classifier
that scores every untrusted message on a ``[0.0, 1.0]`` prompt-
injection confidence and fuses that score into the existing L2
detection.

Design goals
------------

* **Zero mandatory deps.** ``onnxruntime`` and ``tokenizers`` live in
  the ``ml`` extras group. A stock ``pip install cerberus-ai`` still
  works with zero ML code loaded. The classifier is opt-in via
  :attr:`CerberusConfig.ml_injection_enabled`.

* **Latency-bounded.** Every call is bounded by
  ``max_latency_ms`` (default 30 ms); if inference runs over, the
  classifier returns ``0.0`` and logs a warning rather than stalling
  the inspector. Cerberus SLO is sub-100 ms total per turn.

* **Fail-open on classifier error, not on config error.** If the
  classifier raises at inference time we log and return ``0.0`` — the
  regex L2 layer still runs. But if the config enables ML and the
  model file is missing, :func:`build_ml_classifier` raises at
  startup so the operator notices before running unprotected.

* **Testable without weights.** The classifier accepts a
  ``predict_override`` callable so tests and offline runs can swap in
  a deterministic function. No ONNX model is shipped with the OSS
  repo — operators point :attr:`CerberusConfig.ml_injection_model_path`
  at a model file they download separately.
"""
from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

logger = logging.getLogger("cerberus.ml.injection")

# Public type alias — a pure function from text to a confidence score
# in [0, 1]. Used by tests and by operators who want to run their own
# model instead of the bundled ONNX path.
PredictFn = Callable[[str], float]


# Default decision threshold. Chosen to keep false-positive rate
# low (~<1%) on the Anthropic/Microsoft prompt-injection benchmarks —
# operators can override per deployment.
DEFAULT_THRESHOLD: float = 0.75
DEFAULT_MAX_LATENCY_MS: int = 30
DEFAULT_MAX_INPUT_CHARS: int = 4096


class MLInjectionClassifier:
    """Small-model prompt-injection classifier.

    Parameters
    ----------
    model_path:
        Filesystem path to an ONNX file. Required unless
        ``predict_override`` is supplied.
    tokenizer_path:
        Filesystem path to a HuggingFace ``tokenizer.json``. Required
        unless ``predict_override`` is supplied.
    threshold:
        Scores at or above this are treated as prompt-injection hits
        and fused into L2 detection.
    max_latency_ms:
        Soft deadline. If inference takes longer, the classifier
        returns ``0.0`` and the regex layer stands alone for that
        message.
    max_input_chars:
        Input text is truncated to this length before tokenisation.
        Stops an attacker from using a 1 MB message to force a long
        inference and blow the latency budget.
    predict_override:
        If supplied, bypasses ONNX entirely and uses this function.
        Exists so unit tests can pin scores without carrying a model
        in the repo, and so operators can drop in a different
        implementation (e.g. a remote gRPC model server) without
        subclassing.
    """

    def __init__(
        self,
        *,
        model_path: str | Path | None = None,
        tokenizer_path: str | Path | None = None,
        threshold: float = DEFAULT_THRESHOLD,
        max_latency_ms: int = DEFAULT_MAX_LATENCY_MS,
        max_input_chars: int = DEFAULT_MAX_INPUT_CHARS,
        predict_override: PredictFn | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError(
                f"threshold must be in [0, 1], got {threshold!r}"
            )
        if max_latency_ms <= 0:
            raise ValueError(
                f"max_latency_ms must be > 0, got {max_latency_ms!r}"
            )
        if max_input_chars <= 0:
            raise ValueError(
                f"max_input_chars must be > 0, got {max_input_chars!r}"
            )

        self._threshold = float(threshold)
        self._max_latency_ms = int(max_latency_ms)
        self._max_input_chars = int(max_input_chars)
        self._predict_override: PredictFn | None = predict_override

        self._session: Any | None = None
        self._tokenizer: Any | None = None
        self._input_name: str | None = None

        if predict_override is None:
            # Eager load — we want config errors (missing model file,
            # extras not installed) to fail at process start, not on
            # the first adversarial message three hours in.
            if model_path is None or tokenizer_path is None:
                raise ValueError(
                    "MLInjectionClassifier requires both model_path and "
                    "tokenizer_path when no predict_override is given"
                )
            self._load_onnx(Path(model_path), Path(tokenizer_path))

    def _load_onnx(self, model_path: Path, tokenizer_path: Path) -> None:
        """Import onnxruntime + tokenizers lazily and hold the session."""
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer
        except ImportError as exc:
            raise ImportError(
                "cerberus_ai.ml_injection requires the 'ml' extras. "
                "Install with: pip install 'cerberus-ai[ml]'"
            ) from exc

        if not model_path.is_file():
            raise FileNotFoundError(
                f"ML injection model not found: {model_path}"
            )
        if not tokenizer_path.is_file():
            raise FileNotFoundError(
                f"ML injection tokenizer not found: {tokenizer_path}"
            )

        # CPU-only by default — operators can set the provider
        # environment variable if they want GPU; we don't assume it.
        self._session = ort.InferenceSession(
            str(model_path),
            providers=["CPUExecutionProvider"],
        )
        self._tokenizer = Tokenizer.from_file(str(tokenizer_path))
        self._input_name = self._session.get_inputs()[0].name
        logger.info(
            "MLInjectionClassifier loaded: model=%s tokenizer=%s",
            model_path.name, tokenizer_path.name,
        )

    # ── public API ─────────────────────────────────────────────────

    @property
    def threshold(self) -> float:
        return self._threshold

    @property
    def max_latency_ms(self) -> int:
        return self._max_latency_ms

    def score(self, text: str) -> float:
        """Return the injection confidence in ``[0.0, 1.0]``.

        Bounded by :attr:`max_latency_ms`: inference runs on a daemon
        worker thread and the caller is released when the budget
        elapses. A timed-out thread is left to finish in the
        background (no cooperative cancellation is possible for a
        C-extension ONNX call) but never blocks the inspector beyond
        the budget.

        Fail-open: exceptions and timeouts are logged and return
        ``0.0`` so the regex L2 layer is still authoritative. A valid
        score that completes *within* the budget is always returned
        — the security gain of the classifier is not discarded.
        """
        if not text or not text.strip():
            return 0.0

        if len(text) > self._max_input_chars:
            text = text[: self._max_input_chars]

        # Slot indexed by object identity of the worker; guards
        # against a previous (timed-out) thread racing a later call
        # and overwriting its result. Only the current worker's
        # writes are observed.
        outcome: dict[str, Any] = {}

        def _worker() -> None:
            try:
                if self._predict_override is not None:
                    outcome["value"] = float(self._predict_override(text))
                else:
                    outcome["value"] = self._run_onnx(text)
            except Exception as exc:   # noqa: BLE001 — fail-open by design
                outcome["error"] = exc

        thread = threading.Thread(
            target=_worker,
            daemon=True,
            name="cerberus-ml-inject",
        )
        thread.start()
        thread.join(timeout=self._max_latency_ms / 1000.0)

        if thread.is_alive():
            # Budget exhausted *and* inference still running — we
            # genuinely saved the caller from a stall. The thread
            # keeps executing as a daemon and will be reaped on
            # process exit; its eventual result is discarded.
            logger.warning(
                "MLInjectionClassifier exceeded latency budget "
                "(>%d ms); returning 0.0 (regex L2 unaffected)",
                self._max_latency_ms,
            )
            return 0.0

        err = outcome.get("error")
        if err is not None:
            logger.warning(
                "MLInjectionClassifier inference failed; "
                "returning 0.0 (regex L2 unaffected)",
                exc_info=err,
            )
            return 0.0

        raw = outcome.get("value")
        if raw is None:
            # Should be unreachable — thread finished but left no
            # result. Treat as inference failure.
            logger.warning(
                "MLInjectionClassifier produced no result; "
                "returning 0.0 (regex L2 unaffected)"
            )
            return 0.0

        # Clamp defensively — an override function may misbehave.
        return max(0.0, min(1.0, float(raw)))

    def is_injection(self, text: str) -> bool:
        """Convenience: :meth:`score` ``>=`` :attr:`threshold`."""
        return self.score(text) >= self._threshold

    # ── internals ──────────────────────────────────────────────────

    def _run_onnx(self, text: str) -> float:
        """Run the ONNX model and return a [0, 1] injection probability.

        Assumes the model is a binary classifier with logits of shape
        ``(1, 2)`` — class 1 being the injection class. This matches
        the distilled DeBERTa-small reference model shipped via the
        ``cerberus-ai-models`` side package; operators with a different
        head shape should supply a ``predict_override`` instead.
        """
        session = self._session
        tokenizer = self._tokenizer
        input_name = self._input_name
        if session is None or tokenizer is None or input_name is None:
            raise RuntimeError(
                "MLInjectionClassifier ONNX session is not initialised"
            )

        enc = tokenizer.encode(text)
        ids = enc.ids

        # onnxruntime needs a numpy int64 array; we keep numpy as a
        # deferred import so users on pure-regex stay numpy-free.
        import numpy as np

        tokens = np.asarray([ids], dtype=np.int64)
        outputs = session.run(None, {input_name: tokens})
        logits = np.asarray(outputs[0])[0]

        # softmax on a length-2 vector — stable implementation
        logits = logits - logits.max()
        probs = np.exp(logits)
        probs = probs / probs.sum()
        return float(probs[1])


def build_ml_classifier_from_config(config: Any) -> MLInjectionClassifier | None:
    """Factory called by :class:`cerberus_ai.Cerberus`.

    Returns ``None`` when ``ml_injection_enabled`` is False. Raises
    if enabled but misconfigured — better to fail at startup than
    run silently with the ML layer disabled.
    """
    if not getattr(config, "ml_injection_enabled", False):
        return None

    model_path = getattr(config, "ml_injection_model_path", None)
    tokenizer_path = getattr(config, "ml_injection_tokenizer_path", None)
    if not model_path or not tokenizer_path:
        raise ValueError(
            "ml_injection_enabled=True requires both "
            "ml_injection_model_path and ml_injection_tokenizer_path"
        )

    return MLInjectionClassifier(
        model_path=model_path,
        tokenizer_path=tokenizer_path,
        threshold=getattr(config, "ml_injection_threshold", DEFAULT_THRESHOLD),
        max_latency_ms=getattr(
            config, "ml_injection_max_latency_ms", DEFAULT_MAX_LATENCY_MS,
        ),
    )
