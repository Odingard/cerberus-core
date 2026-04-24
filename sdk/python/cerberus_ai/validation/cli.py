"""
cerberus_ai.validation.cli
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Command-line entry point for the validation harness.

Usage::

    python -m cerberus_ai.validation.cli \\
        --corpus builtin \\
        --out out/v1.4-baseline \\
        [--fail-f1-below 0.80]

The command is also exposed as ``cerberus validate`` via the
``cerberus`` console script declared in ``pyproject.toml`` (added
alongside the existing ``cerberus discover`` entry point).

Exit codes
----------

* ``0`` — report written successfully; no regression gate breached.
* ``1`` — report written, but overall F1 was below
  ``--fail-f1-below``. Intended for CI gating.
* ``2`` — usage error (bad flag, corpus path missing, etc.).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cerberus_ai.validation.corpus import build_builtin_corpus, load_jsonl_corpus
from cerberus_ai.validation.report import render_markdown_report, write_report
from cerberus_ai.validation.runner import run_corpus
from cerberus_ai.validation.schema import RunnerConfig, ValidationCorpus

_DEFAULT_OUT_DIR = Path("./out/cerberus-validation")


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cerberus validate",
        description="Run the Cerberus validation harness against a corpus.",
    )
    parser.add_argument(
        "--corpus",
        default="builtin",
        help=(
            "Either ``builtin`` (the shipped N ≥ 5000 synthetic corpus) "
            "or a path to a JSONL corpus on disk."
        ),
    )
    parser.add_argument(
        "--out",
        default=str(_DEFAULT_OUT_DIR),
        help="Directory to write ``report.json`` + ``report.md`` into.",
    )
    parser.add_argument(
        "--fail-f1-below",
        type=float,
        default=None,
        help=(
            "If overall F1 is strictly below this threshold, exit 1. "
            "Use in CI to gate releases on detection quality."
        ),
    )
    parser.add_argument(
        "--n",
        type=int,
        default=None,
        dest="max_cases",
        help=(
            "Cap the corpus at the first N cases after stratified "
            "generation. Useful for CI smoke runs; not a substitute "
            "for the full baseline."
        ),
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Emit per-case progress to stderr.",
    )
    return parser.parse_args(argv)


def _load_corpus(spec: str) -> ValidationCorpus:
    if spec == "builtin":
        return build_builtin_corpus()
    path = Path(spec)
    if not path.exists():
        raise SystemExit(f"error: corpus file not found: {path}")
    return load_jsonl_corpus(path)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    corpus = _load_corpus(args.corpus)
    if args.max_cases is not None and args.max_cases < corpus.size:
        corpus = ValidationCorpus(
            corpus_id=corpus.corpus_id,
            version=corpus.version,
            cases=corpus.cases[: args.max_cases],
        )
    if args.verbose:
        print(
            f"[cerberus-validate] corpus={corpus.corpus_id} "
            f"v{corpus.version} size={corpus.size}",
            file=sys.stderr,
        )

    report = run_corpus(corpus, runner_config=RunnerConfig(verbose=args.verbose))

    json_path = write_report(report, out_dir / "report.json")
    md_path = out_dir / "report.md"
    md_path.write_text(render_markdown_report(report), encoding="utf-8")

    print(f"wrote {json_path}")
    print(f"wrote {md_path}")

    # Gate on the *block*-layer F1 (the "did Cerberus block when it should?"
    # decision). The ``overall`` confusion matrix uses a loose "any expected /
    # any actual" heuristic which, on the built-in corpus where every case
    # has ``expected.l1 = True`` and L1 fires baseline-true, always scores
    # 1.0 — so gating on ``overall`` would make ``--fail-f1-below`` a no-op.
    # Block F1 is the product-relevant number and the one the published
    # baseline + CHANGELOG quote.
    block_layer = report.layers.get("block")
    gate_f1 = block_layer.f1 if block_layer is not None else (
        report.overall.f1 if report.overall else 0.0
    )
    if args.fail_f1_below is not None and gate_f1 < args.fail_f1_below:
        print(
            f"FAIL: block F1 {gate_f1:.3f} < threshold "
            f"{args.fail_f1_below:.3f}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
