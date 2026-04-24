"""
cerberus_ai.validation
~~~~~~~~~~~~~~~~~~~~~~~

Offline validation harness for Cerberus (v1.4 Delta #5).

The module provides a deterministic, reproducible, binary-fixture-free
way to measure how Cerberus performs against a large corpus of adversarial
and benign turns — the number that goes on the side of a product and has
to survive a hostile read.

Three surfaces:

* :mod:`~cerberus_ai.validation.schema` — serialisable models for
  cases, corpora, and reports.
* :mod:`~cerberus_ai.validation.corpus` — built-in synthetic generator
  (N ≥ 5000 cases across Trifecta / L1-only / L2-only / L3-only /
  benign) plus readers for JSONL-on-disk corpora.
* :mod:`~cerberus_ai.validation.runner` — executes a corpus through
  a configured :class:`~cerberus_ai.Cerberus` instance and produces a
  :class:`~cerberus_ai.validation.schema.ValidationReport`.

The CLI wrapper (:mod:`~cerberus_ai.validation.cli`) is wired into the
``cerberus`` console script so operators can run
``cerberus validate --corpus builtin`` in CI and publish a machine-readable
metric alongside every release.
"""
from __future__ import annotations

from cerberus_ai.validation.corpus import (
    BUILTIN_CORPUS_VERSION,
    build_builtin_corpus,
    load_jsonl_corpus,
)
from cerberus_ai.validation.report import render_markdown_report, write_report
from cerberus_ai.validation.runner import run_corpus
from cerberus_ai.validation.schema import (
    CaseCategory,
    ConfusionMatrix,
    ExpectedDetection,
    LayerMetrics,
    RunnerConfig,
    ValidationCase,
    ValidationCorpus,
    ValidationReport,
)

__all__ = [
    "BUILTIN_CORPUS_VERSION",
    "CaseCategory",
    "ConfusionMatrix",
    "ExpectedDetection",
    "LayerMetrics",
    "RunnerConfig",
    "ValidationCase",
    "ValidationCorpus",
    "ValidationReport",
    "build_builtin_corpus",
    "load_jsonl_corpus",
    "render_markdown_report",
    "run_corpus",
    "write_report",
]
