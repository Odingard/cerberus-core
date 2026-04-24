"""
cerberus_ai.validation.report
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Writes / renders :class:`ValidationReport` artifacts.

Two surfaces:

* :func:`write_report` — canonical JSON, for CI gates and dashboards.
* :func:`render_markdown_report` — human-readable summary suitable
  for release notes, GitHub issue bodies, and the LinkedIn post
  template. Numbers are emitted to three significant figures; no
  claim is made that cannot be recomputed from the JSON.
"""
from __future__ import annotations

from pathlib import Path

from cerberus_ai.validation.schema import LayerMetrics, ValidationReport

# ── JSON emit ─────────────────────────────────────────────────────────────────


def write_report(report: ValidationReport, path: str | Path) -> Path:
    """Write the report as pretty-printed JSON to ``path``.

    Returns the resolved :class:`Path`. The file is overwritten if
    it exists; parent directories are created as needed.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return p


# ── Markdown emit ─────────────────────────────────────────────────────────────


def _fmt_pct(x: float) -> str:
    return f"{x * 100:.1f}%"


def _fmt_us(x: int) -> str:
    if x < 1_000:
        return f"{x} µs"
    if x < 1_000_000:
        return f"{x / 1_000:.2f} ms"
    return f"{x / 1_000_000:.2f} s"


def _layer_row(layer: LayerMetrics) -> str:
    m = layer.matrix
    return (
        f"| `{layer.name}` | {m.total} | {m.true_positive} | {m.false_positive} | "
        f"{m.false_negative} | {m.true_negative} | "
        f"{_fmt_pct(layer.precision)} | {_fmt_pct(layer.recall)} | "
        f"{layer.f1:.3f} | {_fmt_pct(layer.false_positive_rate)} |"
    )


def render_markdown_report(report: ValidationReport) -> str:
    """Render a release-note-ready markdown summary."""
    lines: list[str] = []
    lines.append(f"# Cerberus validation report — v{report.cerberus_version}")
    lines.append("")
    lines.append(
        f"_Corpus `{report.corpus_id}` v{report.corpus_version}, "
        f"N = {report.corpus_size}, "
        f"wall-clock {report.duration_ms / 1000:.2f} s_"
    )
    lines.append("")

    # ── Headline ──
    #
    # The *product-relevant* headline is block precision / recall:
    # "did Cerberus block the turn, and was that the right call?"
    # Per-layer L1/L3 numbers are diagnostic; they tend to look
    # baseline-saturated under a realistic agent config (where
    # outbound-capable tools are declared up-front), so they are
    # *not* the honest summary of how the product performs.
    block = report.layers.get("block")
    if block is not None:
        m = block.matrix
        # Benign FP rate is the single most-asked metric from
        # CISOs / buyers: "how often will this block my users doing
        # nothing wrong?" Pull it from the per-category breakdown
        # so it matches a buyer's intuition.
        benign_cat = next(
            (c for c in report.categories if c.category.value == "benign"),
            None,
        )
        benign_fp_rate = benign_cat.block_rate if benign_cat is not None else 0.0
        trifecta_cat = next(
            (c for c in report.categories if c.category.value == "trifecta"),
            None,
        )
        trifecta_block_rate = (
            trifecta_cat.block_rate if trifecta_cat is not None else 0.0
        )
        lines.append("## Headline")
        lines.append("")
        lines.append(
            f"- **Trifecta block recall** (true attacks caught): "
            f"{_fmt_pct(trifecta_block_rate)}"
        )
        lines.append(
            f"- **Block precision** (blocks that were real attacks): "
            f"{_fmt_pct(block.precision)}"
        )
        lines.append(
            f"- **Block recall** (attacks across all attack mixes): "
            f"{_fmt_pct(block.recall)}"
        )
        lines.append(f"- **Block F1**: {block.f1:.3f}")
        lines.append(
            f"- **False-positive rate on benign traffic**: "
            f"{_fmt_pct(benign_fp_rate)}"
        )
        lines.append(
            f"- **Cases scored correctly (block decision)**: "
            f"{m.true_positive + m.true_negative} / {m.total}"
        )
        lines.append("")

    # ── Per-layer table ──
    lines.append("## Per-layer metrics")
    lines.append("")
    lines.append(
        "| Layer | N | TP | FP | FN | TN | Precision | Recall | F1 | FPR |"
    )
    lines.append(
        "|-------|---|----|----|----|----|-----------|--------|----|-----|"
    )
    for layer in ("l1", "l2", "l3", "trifecta", "block"):
        if layer in report.layers:
            lines.append(_layer_row(report.layers[layer]))
    lines.append("")

    # ── Per-category breakdown ──
    lines.append("## Per-category detection")
    lines.append("")
    lines.append("| Category | N | Detected | Detection rate | Blocked | Block rate |")
    lines.append("|----------|---|----------|----------------|---------|------------|")
    for c in report.categories:
        lines.append(
            f"| `{c.category.value}` | {c.total} | {c.detected} | "
            f"{_fmt_pct(c.detection_rate)} | {c.blocked} | "
            f"{_fmt_pct(c.block_rate)} |"
        )
    lines.append("")

    # ── Latency ──
    lines.append("## Latency")
    lines.append("")
    lines.append(f"- **Mean per-turn**: {_fmt_us(report.mean_latency_us)}")
    lines.append(f"- **p95**: {_fmt_us(report.p95_latency_us)}")
    lines.append(f"- **Max**: {_fmt_us(report.max_latency_us)}")
    lines.append("")

    lines.append("---")
    lines.append(
        "_Generated by `cerberus validate`. Numbers are reproducible — "
        "`python -m cerberus_ai.validation.cli --corpus builtin --out out/` "
        "emits a bit-identical report._"
    )
    return "\n".join(lines)
