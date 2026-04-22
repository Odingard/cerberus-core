"""
cerberus_ai.async_inspect
~~~~~~~~~~~~~~~~~~~~~~~~~
Non-blocking inspection handle (Sprint 2 §3.3).

``Cerberus.inspect_async_nonblocking()`` returns an
:class:`InspectionHandle` immediately. The inspection itself runs on a
background thread (not in the caller's event loop) so the calling
agent can continue producing the turn and only *block* on the handle
when it actually needs the verdict (e.g. before emitting the tool
call). Callbacks can be registered for fire-and-forget wiring into
Observe or a user-supplied SIEM.

Contract:

    handle = cerberus.inspect_async_nonblocking(messages, tool_calls)
    handle.on_block(lambda result: sink.notify(result))
    handle.on_complete(lambda result: metrics.record(result))
    ...
    result = handle.result(timeout=0.25)   # blocks up to 250ms

``result(timeout=0)`` is non-blocking and raises
:class:`InspectionStillRunning` if the inspection hasn't finished.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import Future

from cerberus_ai.models import InspectionResult


class InspectionStillRunning(RuntimeError):  # noqa: N818  (public API, kept stable for v1.x)
    """Raised by ``InspectionHandle.result(timeout=0)`` if still pending."""


class InspectionHandle:
    """
    Handle to an in-flight :meth:`Cerberus.inspect_async_nonblocking` call.

    Callbacks are fired exactly once from the inspection worker thread.
    Exceptions in callbacks are swallowed and logged; they never leak
    into the inspector's hot path.
    """

    def __init__(self, future: Future[InspectionResult]) -> None:
        self._future = future
        self._lock = threading.Lock()
        self._complete_cbs: list[Callable[[InspectionResult], None]] = []
        self._block_cbs: list[Callable[[InspectionResult], None]] = []
        self._future.add_done_callback(self._on_done)

    # ── Public API ────────────────────────────────────────────────

    def result(self, timeout: float | None = None) -> InspectionResult:
        """
        Block for up to ``timeout`` seconds (None = forever, 0 = raise if pending).

        Raises :class:`InspectionStillRunning` when ``timeout == 0`` and the
        inspection hasn't completed yet. Any exception raised by the
        underlying inspector is re-raised here.
        """
        if timeout == 0 and not self._future.done():
            raise InspectionStillRunning(
                "Inspection still running; pass timeout>0 to wait."
            )
        return self._future.result(timeout=timeout)

    def done(self) -> bool:
        return self._future.done()

    def on_complete(
        self, callback: Callable[[InspectionResult], None]
    ) -> InspectionHandle:
        """Fire ``callback`` with the final result regardless of outcome."""
        with self._lock:
            if self._future.done():
                self._dispatch(callback)
            else:
                self._complete_cbs.append(callback)
        return self

    def on_block(
        self, callback: Callable[[InspectionResult], None]
    ) -> InspectionHandle:
        """Fire ``callback`` only when the inspection result is blocked."""
        with self._lock:
            if self._future.done():
                result = self._safe_result()
                if result is not None and result.blocked:
                    self._dispatch(callback, result)
            else:
                self._block_cbs.append(callback)
        return self

    def cancel(self) -> bool:
        """Attempt to cancel. Returns True if the worker hadn't started yet."""
        return self._future.cancel()

    # ── Private ───────────────────────────────────────────────────

    def _safe_result(self) -> InspectionResult | None:
        try:
            return self._future.result(timeout=0)
        except Exception:
            return None

    def _dispatch(
        self,
        callback: Callable[[InspectionResult], None],
        result: InspectionResult | None = None,
    ) -> None:
        if result is None:
            result = self._safe_result()
        if result is None:
            return
        try:
            callback(result)
        except Exception:  # noqa: BLE001 — callback exceptions are user bugs
            import logging

            logging.getLogger("cerberus.async").exception(
                "InspectionHandle callback raised"
            )

    def _on_done(self, _future: Future[InspectionResult]) -> None:
        with self._lock:
            complete_cbs = list(self._complete_cbs)
            block_cbs = list(self._block_cbs)
            self._complete_cbs.clear()
            self._block_cbs.clear()
        result = self._safe_result()
        if result is None:
            return
        for cb in complete_cbs:
            self._dispatch(cb, result)
        if result.blocked:
            for cb in block_cbs:
                self._dispatch(cb, result)
