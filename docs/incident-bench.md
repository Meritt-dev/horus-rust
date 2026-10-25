# IncidentBench

IncidentBench measures whether an incident-investigation tool brings back the right past
incident when a new one starts, and stays quiet when nothing related exists. Version 0
covers one task: startup recall.

## Task: startup recall

Each case is one codebase's investigation history. The runner replays it in time order. For
each investigation it asks the tool for related past incidents, using only what existed
before that moment, then stores the investigation as memory for later steps.

- **Found**: share of repeat investigations (an earlier one in the same family exists) whose
  top three recalled incidents include a family member.
- **Clean**: share of non-repeat investigations where the tool recalls nothing.

Report both, per codebase and pooled. Neither number means anything alone.

## Labels

A family is a set of investigations about the same underlying problem or the same specific
failing operation, so that seeing the earlier one would genuinely help with the later one.
Broad area overlap does not count.

- Real codebases: at least two independent reviewers label each history without seeing any
  tool output. Report agreement and score against every label set.
- Synthetic codebases: families are defined when the history is written, so the truth is
  known by construction.

## Avoiding overfitting

Tune nothing on the codebase being scored. Choose settings with leave-one-codebase-out
validation: fit on all other codebases, score the held-out one, pool the held-out results.

## Case format

```json
{
  "codebase": "name",
  "investigations": [
    {
      "id": "…",
      "createdAt": "ISO-8601",
      "report": {
        "input": { "hint": "…", "repo": "name" },
        "summary": "…",
        "seeds": [],
        "hypotheses": [],
        "timeline": { "boundaryCrossings": [] },
        "suspectedCauses": []
      }
    }
  ],
  "labels": { "<label set>": [["id", "…"], ["id"]] },
  "vectors": { "<hint text>": { "q": [0.1], "d": [0.1] } }
}
```

`vectors` are optional precomputed query and document embeddings of each hint, so the
embedding lane replays exactly without a model host. Without them, only keyword matching is
measured. Cases built from real client histories stay private and are never committed.

## Running

The runner replays through the real recall and capture code in a disposable SQLite file, so it
never touches saved investigations:

```sh
HORUS_BENCH_CASES=<dir> HORUS_BENCH_OUT=bench-result.json cargo run -q -p horus-engine --example incident_bench
```

## Public cases

`bench/incident/cases/` holds three synthetic codebases (payments, logistics, B2B SaaS) with ground
truth defined at authoring time and precomputed hint vectors. Generated data; not formatted.

- **realistic**: repeats calibrated to the similarity profile of real histories (share of
  repeats whose closest earlier family member scores ≥0.80 / 0.70–0.80 / <0.70: real 66% /
  25% / 9%, realistic 55% / 36% / 9%). Use this track for headline numbers.
- **hard**: the same codebases before calibration. Repeats are mostly adversarial rewordings
  and findings-only follow-ups (only 7% score ≥0.80). Use it to show headroom, not quality.

## Current reference results

Horus startup recall, October 2026. The public-track rows are reproduced exactly by the runner
above; the real-codebase row comes from held-out label sets that are not published.

| Set                                                                             | Old word-overlap rule | Shipped recall          | Shipped, keyword-only fallback |
| ------------------------------------------------------------------------------- | --------------------- | ----------------------- | ------------------------------ |
| Six real codebases, leave-one-codebase-out (384 investigations, two label sets) | 63–67% found          | 79–83% found, 96% clean | 72–74% found, 96–97% clean     |
| Public realistic track (460 investigations)                                     | 51% found, 100% clean | 79% found, 99% clean    | 63% found, 100% clean          |
| Public hard track (180 investigations)                                          | 10% found, 100% clean | 18% found, 98% clean    | 16% found, 100% clean          |
