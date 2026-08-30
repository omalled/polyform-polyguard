# Proposed Polyform implementation remediation workflow

This proposal is an operator-centered target design. The lifecycle evaluation will annotate it
with what the current CLI and dashboard actually support.

## Identity and states

An implementation identity is immutable code plus provenance. Repair never rewrites an existing
identity; it creates a new implementation that records `supersedes`, preserving evidence and
audit history. Recommended states are:

```text
active → investigate → quarantined → superseded
   ↑          |             |
   └──────────┴── restore ──┘
```

`investigate` is advisory but visible. `quarantined` is excluded from new compositions and
triggers safe recomposition. `superseded` is terminal for new assignments but retains historical
telemetry. Restore is permitted only from `investigate` or `quarantined` after fresh gates and a
signed operator action; it never applies to code replaced under a new identity.

## Commands

### `polyform implementations investigate <id>`

Shows status history, source/release provenance, affected compositions, aggregate outcome and
latency deltas, first/last event, correlated test labels, and attached reproductions. With
`--mark`, records `active → investigate` plus an operator reason. Marking is non-disruptive and
may be automated by an alert rule, but the dashboard must distinguish automatic from human state.

### `polyform implementations reproduce <id>`

Downloads a privacy-reviewed evidence bundle containing the exact release manifest, composition,
function contract, implementation source digest, tool versions, deterministic seed, and a
minimized typed input when that input is explicitly safe to retain. It verifies signatures and
runs the implementation in an isolated worktree against the exact accepted peers. Raw production
request data is never exported. If no safe case exists, it provides a synthetic generator recipe
and correlation metadata rather than payload content.

### `polyform implementations quarantine <id>`

Preconditions: current project/release selected, impact preview acknowledged, reason supplied,
minimum diversity can still be met or an explicit release-disable decision is made, and the
operator has quarantine permission. The command atomically records the state transition, excludes
the identity from new compositions, recomposes affected installations, and exposes rollout
progress. `--dry-run` is mandatory in automation before mutation. Existing clients retain their
last known safe composition only until the configured lease expires; a client that cannot obtain
the minimum safe width fails closed.

### `polyform implementations repair <id>`

Creates an isolated repair branch and a new candidate identity linked by `derived_from`. It
includes the minimized regression first, then invokes a coding agent with the original contract,
diversity brief, failure evidence, and peer approaches to avoid. Admission requires shared
conformance, permanent regression, differential agreement on accepted/rejected corpora,
substantial seeded fuzzing, resource bounds, application integration, and reproducible build
evidence. It never edits the published identity in place.

### `polyform implementations replace <old-id> <new-id>`

Requires the new identity to be admitted and compatible with the same function contract. It
publishes a signed patch release whose manifest records `supersedes`, recomposes clients in a
staged rollout, and moves the old identity to `superseded` after health criteria pass. Rollback
creates another signed release/composition transition; it does not erase history.

### `polyform implementations verify <id>`

Runs or verifies the complete admission matrix and emits signed evidence tied to source, spec,
tests, corpus digests, toolchain, and release candidate. Stale source/spec/test/corpus changes
invalidate the evidence. The command reports every gate, not only a single pass/fail bit.

### `polyform implementations restore <id>`

Allowed only when the exact identity has no code changes, the original issue is shown to be a
spec/test/integration/telemetry false positive or a fixed external cause, regression coverage is
present, verification evidence is fresh, and an operator approves the impact preview. It records
`investigate|quarantined → active`, then performs a gradual recomposition. It cannot silently
clear evidence or alerts.

## Automation and human review

Automation may detect anomalies, mark `investigate`, minimize synthetic cases, run reproductions,
build candidates, execute gates, and prepare impact previews. Quarantine may be automatic only
under a preauthorized high-confidence policy with minimum-diversity and fail-closed checks.
Restoring, superseding, and signing a release require human review by default.

## Dashboard

The implementation page should unify status, code/release provenance, composition exposure,
counterfactual peer comparisons, time-series outcomes, latency distributions, test labels,
evidence attachments, and audit events. It should answer “why was this flagged?” and “which safe
action is next?” without exposing request content. The release page should show recomposition
progress and installations that cannot satisfy the minimum diversity width.

## Audit and rollback

Every state change is append-only, signed or server-attributed, timestamped, and includes actor,
reason, evidence digests, affected releases, impact preview, and resulting compositions. Rollback
is an explicit new event and, when code selection changes, a new signed release or composition
revision. Historical telemetry remains queryable under the identity and release that produced it.
