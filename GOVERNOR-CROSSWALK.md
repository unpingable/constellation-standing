# Governor ↔ Standing Crosswalk

> **Status (2026-05-20):** Standing-side primitive shipped; AG-side adoption exists; this remains a crosswalk/reference, not a current integration plan. Body retains pre-rename "nq-standing" naming.

Governor is nq-standing for agents. nq-standing is Governor for production workloads.

## Correspondence table

| nq-standing concept | Governor equivalent |
|---|---|
| Short-lived scoped grant | Override with sunset clause |
| Grant renewal tracking | Override accumulation / pressure signal |
| Decision receipt | GateReceipt (content-addressed, policy_hash) |
| Policy evaluation | Gate evaluation (evidence + policy → verdict) |
| Stale/expired grants | Fact decay, TTL enforcement |
| Scope on grants (actor×target×action×duration) | Scope governor (tool×resource×axes) |
| "Why was this allowed?" | `governor receipts --id <id> --evidence` |
| Standing drift | Claim diff, drift detection |
| Revocation between issuance and use | TOCTOU — atomic transactions |

## WLP as bridge — RETIRED 2026-09-20

**Not pursued. Do not reintroduce.** WLP is retired from this integration with
no named consumer. Standing's receipt format is its own.

Worth noting for anyone tempted by a similar bridge later: the plan below ended with
"verify with shared test vectors," and that step was the one never taken. Three
implementations of WLP's normatively specified `artifact_hash` drifted apart precisely
because no shared corpus existed to expose it. If a cross-language format is ever
adopted here, the vectors are not the last step — they are the thing that makes the
format real.

Retained below as design history only.

> nq-standing decision receipts are WLP DECISION messages. Options:
> 1. Thin receipt format forward-compatible with WLP (same JSON, same hash, no sigs yet)
> 2. WLP Phase 1 ships as a library consumed by both Governor and nq-standing
>
> Since Governor is Python and nq-standing is Rust: define the receipt format in WLP, implement natively in each language, verify with shared test vectors.

## Key architectural lesson from Governor

"Decision succeeded but receipt write failed" must be solved architecturally, not as an edge case. Governor learned this: fail-open receipt emission means authority without custody.

**nq-standing should be fail-closed.** No receipt, no standing.

## Historical proposed shared primitives (not implemented)

The following list described the retired WLP bridge. It is retained only to
explain the earlier design proposal and is not a current Standing dependency or
compatibility claim.

- Canonical JSON (RFC 8785 / JCS)
- SHA-256 digests
- Content-addressed receipts
- Policy hash pinning
- Evidence freshness semantics

## Taxonomy-derived failure modes

The cybernetic failure taxonomy (~15 Δ-domains) developed across Governor
and the paper series applies directly to standing:

| Failure mode in design doc | Δ-domain | Governor mechanism |
|---|---|---|
| Grant expired, still used | Δw (write-authority drift) | Override sunset clauses |
| Grant revoked between issuance and use | TOCTOU | Atomic transactions, leases |
| Policy changed under live grant | Δm (model drift) | Regime detection |
| Decision OK but receipt write failed | Δo (observability failure) | Fail-closed receipt emission |
| Old grant replayed | Δr (recursion capture) | Taint similarity, scar fingerprints |
| Identity rotated mid-lease | Δb (boundary error) | Scope governor axis validation |
| Standing drift (stale grants accumulate) | Δh (hysteresis) | Override accumulation pressure |
| Receipt missing — action or observation? | Δo vs Δa | Receipt kernel completeness invariant |

The standing design doc's failure modes list is unusually good because
these are the same failure families Governor already has primitives for.
The primitives port; only the substrate changes (agent tool calls → workload auth).

## What Governor should steal back

**Generation-style snapshots of standing state.** nq's generation model
(coherent cut of fleet state at a point in time) applies to standing and
to Governor. Governor's gap spec GOV_GAP_DECISION_CONTEXT_001 proposes
exactly this: content-addressed snapshot of governor state at decision time.
Standing may need it too — "what was the grant/policy landscape when this
decision was made?" Any future convergence on a snapshot-at-decision-time
pattern needs a new, explicitly qualified contract; WLP is retired.

## Naming note

This project ships as `standing`, a sibling of NQ rather than a child. The
earlier idea that a WLP bridge would provide the explicit link was not pursued.
