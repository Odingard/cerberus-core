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

    overall_f1 = report.overall.f1 if report.overall else 0.0
    if args.fail_f1_below is not None and overall_f1 < args.fail_f1_below:
        print(
            f"FAIL: overall F1 {overall_f1:.3f} < threshold "
            f"{args.fail_f1_below:.3f}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
