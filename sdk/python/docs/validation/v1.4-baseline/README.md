# v1.4 baseline — Cerberus validation harness

This folder holds the **published baseline** for Cerberus v1.4 — the
N = 5100 run that every future v1.4.x release is benchmarked against.

## Reproducing

```bash
pip install cerberus-ai
python -m cerberus_ai.validation.cli --corpus builtin --out out/
# artifacts land in out/report.json and out/report.md
```

Same seed, same numbers, bit-identical on every machine. The
corpus generator uses a fixed RNG seed (`BUILTIN_SEED = 1989`) and
the harness writes every case to a deterministic case_id before
scoring.

## What to look at first

The `## Headline` block in `report.md` leads with the four numbers
that actually matter to a buyer:

1. **Trifecta block recall** — of the 200 real-attack cases in the
   corpus, how many did Cerberus block? This is the product
   question. Baseline: **89.5%** (179 / 200).
2. **Block precision** — of every turn Cerberus chose to block,
   how many were real attacks? Baseline: **69.1%**. The gap is
   carried by the L2 regex detector firing on benign assistant
   text that contains homoglyph-adjacent characters (`°`,
   smart-quotes, etc.). This is the layer the v1.4 Delta #2 ML
   classifier is designed to improve on real traffic; it is
   off-by-default in the baseline run.
3. **Benign false-positive rate** — of the 2000 benign cases,
   how many did Cerberus block? Baseline: **14.2%**. Same root
   cause as above. Enabling the ML classifier at
   `high-precision` mode pulls this below the v1.4 target.
4. **Latency** — mean **1.24 ms**, p95 **1.50 ms**, max
   **~5 ms** across all 5100 cases. Well under the
   100 ms median SLA from the v1.4 spec.

## Harness configuration

The default runner config (`default_runner_cerberus_config`)
intentionally declares:

* ten tools (six outbound-capable — `http_post`, `send_email`,
  `webhook`, `notify_slack`, `upload_to_s3`, `dns_lookup`; and
  four data-reading / benign helpers — `get_calendar`,
  `search_docs`, `run_sql`, `translate`), and
* **no explicit data sources**.

That is the shape of a realistic production agent — the agent
*has* network reach, *has* data-reading capability, and is not
going to carry a curated `DataSource[]` registry on day one.
Under that config L1 and L3 fire baseline-true on every turn; the
decision variable for "block this turn" collapses to L2. The
corpus labels reflect that: categories that contain L2 content
(`l2_only`, `l1_l2`, `l2_l3`, `trifecta`) are labelled
`expected_block = True`; everything else is
`expected_block = False`.

An operator running Cerberus against their own fleet, with their
own `CerberusConfig`, should re-run the harness with that config
injected (`run_corpus(corpus, cerberus=Cerberus(my_config))`).
The numbers they get will reflect their agent, not the
public baseline.

## Files

* `report.json` — canonical machine-readable output. Drive CI
  gates off this (the CLI's `--fail-f1-below <threshold>` reads
  the same numbers).
* `report.md` — release-note-ready markdown. This is what gets
  dropped into GitHub release notes and LinkedIn.
