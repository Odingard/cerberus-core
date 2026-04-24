"""
cerberus_ai.validation.schema
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Serialisable models for the offline validation harness.

Design rules
============

* Every field is JSON-serialisable with stock pydantic — no ``bytes``,
  no ``datetime``, no enums that don't round-trip through ``str``.
* Metric names are stable; the ``ValidationReport`` schema is considered
  part of the public surface and downstream tooling (dashboards,
  regression gates) pins on it.
* No dependency on a running :class:`~cerberus_ai.Cerberus`. Reports can
  be re-rendered offline from the saved JSON.
"""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from cerberus_ai import __version__ as cerberus_version


class CaseCategory(str, Enum):
    """Ground-truth category a corpus case belongs to.

    Used to stratify metrics — e.g. "Trifecta detection: 498/500" is a
    vastly stronger claim than "overall detection: 87%" because the
    latter is dominated by whichever category has the most cases.
    """

    TRIFECTA = "trifecta"           # L1 ∧ L2 ∧ L3 — must BLOCK
    L1_ONLY = "l1_only"             # privileged-data access only
    L2_ONLY = "l2_only"             # injection attempt only
    L3_ONLY = "l3_only"             # outbound path present only
    L1_L2 = "l1_l2"                 # injection against privileged data
    L2_L3 = "l2_l3"                 # injected exfil prompt + outbound path
    L1_L3 = "l1_l3"                 # privileged data + outbound path
    BENIGN = "benign"               # nothing should fire


class ExpectedDetection(BaseModel):
    """Ground-truth expectations for a single case.

    Every flag is *independent*: a case can expect L1+L2 without L3 and
    still be valid. Trifecta-active cases are the subset where all three
    are True and ``expected_block`` is True.
    """

    l1: bool = False
    l2: bool = False
    l3: bool = False
    trifecta: bool = False
    expected_block: bool = False


class ValidationCase(BaseModel):
    """A single corpus case.

    ``messages`` is the raw argument handed to :meth:`Cerberus.inspect`
    — a list of ``{"role": str, "content": str}`` dicts. ``tool_calls``
    is the optional second argument. The runner feeds both straight
    through without interpreting them, which means a case authored
    today survives any future Cerberus API addition that keeps
    backwards-compatibility with the v1.3 inspection signature.
    """

    case_id: str
    category: CaseCategory
    description: str = ""
    messages: list[dict[str, str]]
    tool_calls: list[dict[str, object]] | None = None
    expected: ExpectedDetection


class ValidationCorpus(BaseModel):
    """An ordered, versioned collection of cases plus metadata.

    ``corpus_id`` and ``version`` let downstream tooling gate on
    corpus identity — a report generated against ``builtin/v1`` is
    not directly comparable to one generated against ``builtin/v2``.
    """

    corpus_id: str
    version: str
    description: str = ""
    cases: list[ValidationCase] = Field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.cases)

    def by_category(self, category: CaseCategory) -> list[ValidationCase]:
        return [c for c in self.cases if c.category is category]


# ── Metrics ───────────────────────────────────────────────────────────────────


class ConfusionMatrix(BaseModel):
    """Standard binary-classifier counts for one detection axis."""

    true_positive: int = 0
    false_positive: int = 0
    true_negative: int = 0
    false_negative: int = 0

    @property
    def total(self) -> int:
        return (
            self.true_positive
            + self.false_positive
            + self.true_negative
            + self.false_negative
        )

    @property
    def precision(self) -> float:
        denom = self.true_positive + self.false_positive
        return self.true_positive / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.true_positive + self.false_negative
        return self.true_positive / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) else 0.0

    @property
    def false_positive_rate(self) -> float:
        """FP / (FP + TN) — aka fall-out.

        Distinct from (1 - precision). Critical for "how noisy is the
        scanner on benign traffic" because a rare attack class can
        have strong recall while still producing intolerable FP rates.
        """
        denom = self.false_positive + self.true_negative
        return self.false_positive / denom if denom else 0.0


class LayerMetrics(BaseModel):
    """Confusion matrix + headline numbers for a single detection axis."""

    name: str
    matrix: ConfusionMatrix = Field(default_factory=ConfusionMatrix)

    @property
    def precision(self) -> float:
        return self.matrix.precision

    @property
    def recall(self) -> float:
        return self.matrix.recall

    @property
    def f1(self) -> float:
        return self.matrix.f1

    @property
    def false_positive_rate(self) -> float:
        return self.matrix.false_positive_rate


class CategoryBreakdown(BaseModel):
    """Per-category hit rate, for the "Trifecta: 498/500" headline."""

    category: CaseCategory
    total: int = 0
    detected: int = 0
    blocked: int = 0

    @property
    def detection_rate(self) -> float:
        return self.detected / self.total if self.total else 0.0

    @property
    def block_rate(self) -> float:
        return self.blocked / self.total if self.total else 0.0


# ── Runner config + report ────────────────────────────────────────────────────


class RunnerConfig(BaseModel):
    """Tuning knobs for the runner.

    Kept separate from :class:`cerberus_ai.CerberusConfig` because the
    runner's concerns (how many cases, progress reporting, timeouts)
    are orthogonal to Cerberus' own configuration. ``verbose`` is the
    only setting that affects output — everything else purely affects
    runtime behaviour.
    """

    verbose: bool = False
    fail_on_regression_below_f1: float | None = None
    per_case_timeout_ms: int = 1000


class ValidationReport(BaseModel):
    """The artifact that ships with every v1.4+ release.

    Consumers:
    * CI gate — fails the build if overall F1 drops below a pinned
      threshold.
    * Release notes — the human-readable summary is rendered from this.
    * Dashboards — Prometheus + Grafana (Delta #4) scrape the JSON.
    * Marketing — LinkedIn / website quote the ``overall`` block.
    """

    cerberus_version: str = cerberus_version
    corpus_id: str
    corpus_version: str
    corpus_size: int
    duration_ms: int = 0
    layers: dict[str, LayerMetrics] = Field(default_factory=dict)
    categories: list[CategoryBreakdown] = Field(default_factory=list)
    overall: LayerMetrics | None = None
    mean_latency_us: int = 0
    p95_latency_us: int = 0
    max_latency_us: int = 0
