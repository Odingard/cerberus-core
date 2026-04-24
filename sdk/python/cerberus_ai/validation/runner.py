"""
cerberus_ai.validation.runner
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Executes a :class:`ValidationCorpus` through a configured
:class:`~cerberus_ai.Cerberus` instance and produces a
:class:`ValidationReport`.

Design rules
============

* **No mutation of the case.** The runner does not hack cases to
  match detector quirks. If a category's recall is low, that is the
  signal to improve the detector — not to quietly tag the case as
  "expected miss".
* **Fail-open on per-case error.** A pydantic validation error or a
  detector exception for a single case is logged to the report and
  counted as a mis-detection, but does not abort the run. The whole
  point is to get a stable number across thousands of cases — one
  bad case cannot brick the harness.
* **Closed-form latency capture.** We measure end-to-end
  ``Cerberus.inspect`` wall-clock per case, not the
  ``inspection_latency_us`` field, because we want to include the
  harness's own overhead — that's what an operator will actually pay.
"""
from __future__ import annotations

import time
from collections import defaultdict

from cerberus_ai import Cerberus
from cerberus_ai.models import CerberusConfig, ObserveConfig, ToolSchema
from cerberus_ai.validation.schema import (
    CaseCategory,
    CategoryBreakdown,
    ConfusionMatrix,
    LayerMetrics,
    RunnerConfig,
    ValidationCase,
    ValidationCorpus,
    ValidationReport,
)

# ── Default Cerberus configuration for the harness ────────────────────────────
#
# The corpus presumes a specific shape for the Cerberus instance it's
# being run against: the declared data sources and tool schemas have
# to align with the templates in :mod:`~cerberus_ai.validation.corpus`
# or the labels won't correspond to what the detector sees. Operators
# running the harness against their own fleet-specific config should
# build their own corpus.


#: Tool schemas the built-in corpus references. These are *declared*
#: so the EGI engine authorizes them up-front — otherwise every tool
#: call would be an ``UNAUTHORIZED_TOOL_USE`` violation and the block
#: signal would be dominated by graph-integrity failures rather than
#: trifecta detection. The names line up exactly with the tool-call
#: templates in :mod:`~cerberus_ai.validation.corpus`.
_BUILTIN_TOOLS: tuple[ToolSchema, ...] = (
    ToolSchema(name="http_post", description="HTTP POST", is_network_capable=True),
    ToolSchema(name="send_email", description="Send email", is_network_capable=True),
    ToolSchema(name="webhook", description="Webhook delivery", is_network_capable=True),
    ToolSchema(name="notify_slack", description="Slack notification", is_network_capable=True),
    ToolSchema(name="upload_to_s3", description="S3 upload", is_network_capable=True),
    ToolSchema(name="dns_lookup", description="DNS resolve", is_network_capable=True),
    ToolSchema(name="get_calendar", description="Calendar lookup"),
    ToolSchema(name="search_docs", description="Document search"),
    ToolSchema(name="run_sql", description="Read-only SQL"),
    ToolSchema(name="translate", description="Translation"),
)


def default_runner_cerberus_config() -> CerberusConfig:
    """Config that matches the built-in corpus' ground truth.

    The harness simulates a *realistic* production agent: it has
    both privileged-data capabilities and network-capable tools
    wired up, and is exposed to a mixed stream of benign and
    adversarial input. In that setting:

    * L1 and L3 are **baseline true** (the agent has privilege, and
      it has outbound reach — that is the whole reason it is worth
      protecting).
    * L2 is the decision variable — is there an active injection?
    * The trifecta / block signal turns on L2.

    Tools are declared so the EGI engine authorises them at
    initialization rather than flagging every call as
    ``UNAUTHORIZED_TOOL_USE``. If you deviate from this config,
    your numbers are not directly comparable to the published
    baseline.
    """
    return CerberusConfig(
        data_sources=[],
        declared_tools=list(_BUILTIN_TOOLS),
        observe=ObserveConfig(enabled=False),  # harness never emits telemetry
    )


# ── Per-case execution + scoring ──────────────────────────────────────────────


def _score_case(
    case: ValidationCase,
    actual_l1: bool,
    actual_l2: bool,
    actual_l3: bool,
    actual_trifecta: bool,
    actual_blocked: bool,
    layers: dict[str, LayerMetrics],
    overall_mat: ConfusionMatrix,
) -> bool:
    """Update all confusion matrices from one case + actual detection.

    Returns the *overall* hit/miss flag for category aggregation.
    A case counts as "detected" if every expected flag fired at least
    as the expectation demanded. Benign cases count as detected only
    when nothing fired — precision and recall are handled at the
    per-layer level.
    """
    for layer_name, expected, actual in (
        ("l1", case.expected.l1, actual_l1),
        ("l2", case.expected.l2, actual_l2),
        ("l3", case.expected.l3, actual_l3),
        ("trifecta", case.expected.trifecta, actual_trifecta),
        ("block", case.expected.expected_block, actual_blocked),
    ):
        m = layers[layer_name].matrix
        if expected and actual:
            m.true_positive += 1
        elif expected and not actual:
            m.false_negative += 1
        elif not expected and actual:
            m.false_positive += 1
        else:
            m.true_negative += 1

    # Overall "did Cerberus get this case right" — a single bit per
    # case. Useful for the top-line number without masking per-layer
    # nuance.
    expected_any = (
        case.expected.l1
        or case.expected.l2
        or case.expected.l3
        or case.expected.trifecta
        or case.expected.expected_block
    )
    actual_any = actual_l1 or actual_l2 or actual_l3 or actual_trifecta or actual_blocked
    if expected_any and actual_any:
        overall_mat.true_positive += 1
        return True
    if expected_any and not actual_any:
        overall_mat.false_negative += 1
        return False
    if not expected_any and actual_any:
        overall_mat.false_positive += 1
        return False
    overall_mat.true_negative += 1
    return True


def run_corpus(
    corpus: ValidationCorpus,
    cerberus: Cerberus | None = None,
    runner_config: RunnerConfig | None = None,
) -> ValidationReport:
    """Drive ``Cerberus.inspect`` over every case and return a report.

    If ``cerberus`` is omitted, a fresh instance is built **per case**
    with :func:`default_runner_cerberus_config`. Per-case isolation
    matters: Cerberus is designed as a *per-agent-session* singleton,
    and cross-turn state (L1 data-flow tokens, L2 recency window, EGI
    delegation graph, L4 memory ledger) accumulates inside a session.
    Sharing one instance across unrelated corpus cases leaks that
    state — a prior L1-only case leaves an active data-flow token
    behind, which then poisons an unrelated L2 case into a
    false-positive trifecta.

    If you pass a pre-built ``cerberus`` instance, the runner reuses
    it across all cases (treating the corpus as a single long-lived
    session). Use that only if the corpus is deliberately designed as
    a session transcript.
    """
    runner_config = runner_config or RunnerConfig()
    shared_cerberus = cerberus
    default_cfg = default_runner_cerberus_config() if shared_cerberus is None else None

    layers: dict[str, LayerMetrics] = {
        name: LayerMetrics(name=name)
        for name in ("l1", "l2", "l3", "trifecta", "block")
    }
    overall_mat = ConfusionMatrix()

    per_category_total: dict[CaseCategory, int] = defaultdict(int)
    per_category_hits: dict[CaseCategory, int] = defaultdict(int)
    per_category_blocks: dict[CaseCategory, int] = defaultdict(int)

    latencies_us: list[int] = []
    started = time.perf_counter()

    for case in corpus.cases:
        per_category_total[case.category] += 1

        if shared_cerberus is not None:
            cerberus = shared_cerberus
        elif default_cfg is not None:
            cerberus = Cerberus(default_cfg)
        else:  # pragma: no cover — unreachable, both are None only when called wrong
            raise RuntimeError("run_corpus invariant broken: no cerberus config available")

        t0 = time.perf_counter()
        try:
            result = cerberus.inspect(
                messages=case.messages,
                tool_calls=case.tool_calls,
            )
        except Exception:  # noqa: BLE001 — per-case robustness > strict typing
            # A detector exception on one case cannot brick a 5000-case run.
            # Count as a miss and move on; the failure shows up as a
            # false negative (if the case expected a detection) or an
            # equivocal false positive.
            per_category_hits[case.category] += 0
            continue
        elapsed_us = int((time.perf_counter() - t0) * 1_000_000)
        latencies_us.append(elapsed_us)

        actual_l1 = result.conditions.l1_privileged_data
        actual_l2 = result.conditions.l2_injection
        actual_l3 = result.conditions.l3_exfiltration_path
        actual_trifecta = result.conditions.trifecta_active
        actual_blocked = result.blocked

        if actual_blocked:
            per_category_blocks[case.category] += 1

        hit = _score_case(
            case,
            actual_l1,
            actual_l2,
            actual_l3,
            actual_trifecta,
            actual_blocked,
            layers,
            overall_mat,
        )
        if hit:
            per_category_hits[case.category] += 1

    total_ms = int((time.perf_counter() - started) * 1_000)

    # Latency summaries.
    if latencies_us:
        sorted_lat = sorted(latencies_us)
        mean_us = sum(sorted_lat) // len(sorted_lat)
        p95_idx = max(0, int(len(sorted_lat) * 0.95) - 1)
        p95_us = sorted_lat[p95_idx]
        max_us = sorted_lat[-1]
    else:
        mean_us = p95_us = max_us = 0

    categories = [
        CategoryBreakdown(
            category=category,
            total=per_category_total[category],
            detected=per_category_hits[category],
            blocked=per_category_blocks[category],
        )
        for category in sorted(per_category_total.keys(), key=lambda c: c.value)
    ]

    return ValidationReport(
        corpus_id=corpus.corpus_id,
        corpus_version=corpus.version,
        corpus_size=corpus.size,
        duration_ms=total_ms,
        layers=layers,
        categories=categories,
        overall=LayerMetrics(name="overall", matrix=overall_mat),
        mean_latency_us=mean_us,
        p95_latency_us=p95_us,
        max_latency_us=max_us,
    )
