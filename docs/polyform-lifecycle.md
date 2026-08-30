# Polyform lifecycle log

This log distinguishes documented behavior from local workarounds. It will be finalized with
publication, runtime composition, telemetry, dashboard, and remediation results.

## Documentation and CLI

The current documentation was read end-to-end from `https://omalled.com/polyform/` and its
linked installation, project, specification, generation, fuzzing, resolution, runtime,
publishing, and telemetry pages. `polyform-polyroute` was inspected only as a historical reference.

Documented installation command:

```sh
curl -fsSL https://omalled.com/polyform/downloads/install.sh | sh
```

An already installed binary reported `polyform 0.1.0` but lacked the documented `build` and
`vendor-runtime` commands. Reinstalling from the current documented download produced a binary
that still reports `0.1.0` but has a different checksum and includes the documented commands.
Classification: release/versioning discrepancy, not a project-code defect. Workaround: replace
the stale binary through the documented installer.

## Local generation environment

The first sandboxed `polyform generate` could not update Codex's state database. The smallest
workaround was to run the same documented command with permission to access the user's normal
Codex state. Nested implementation agents also initially encountered restricted crates.io name
resolution; dependencies were fetched in the permitted environment and subsequent builds used
the normal Cargo lockfile.

An initial `source_paths` list named future paths (`build.rs`, `vendor`, `fuzz/corpus`, and
`examples`) before they existed. Polyform correctly rejected the missing inputs. Classification:
project configuration defect. Workaround: declare only existing source inputs, then add future
paths when they exist.

The first generation terminal stream detached while its Polyform process continued. Retrying
briefly overlapped the active run, producing one extra independent header candidate and one
rejected body-framing claim. The retry was stopped; the original lifecycle remained the canonical
run. Classification: local process-observability/workflow issue. Final accepted counts will be
reconciled against the generation ledger and manifest.

The generated shared tests contained two internally inconsistent string expectations: an absent
name nominated by `Connection` was omitted despite the specification requiring all nominations,
and a substring count for `Host:` also counted `X-Forwarded-Host:`. Both assertions were corrected
to match the unchanged specification. Classification: generated test defects; no behavioral gate
was weakened.

During the third generation pass, an authority candidate passed behavioral tests but failed the
configured strict lint gate for an elidable lifetime. Polyform correctly recorded it as rejected
and stopped, leaving the changes for review. The candidate was removed rather than represented as
accepted. A retry was stopped before edits when its prompt confirmed that `--count` means new
candidates per selected function rather than the remaining total. Generation then resumed with
explicit `--function` batches sized from the ledger: two new candidates for the six functions at
three accepted implementations, and three for the seven functions at two. Classification: local
workflow recovery following documented CLI semantics; the CLI's fail-stop and retained-worktree
behavior were correct.

## Runtime and dashboard reconnaissance

The installed CLI has no `runtime` or `telemetry` subcommands, which is consistent with the
current documentation: `polyform vendor-runtime` supplies the Rust client, and applications call
`Client::register`, `refresh`, and `report_execution`. A signed server composition selects one
primary implementation per specified function. Polyguard's local agreement layer will treat that
identity as the primary and add independently admitted local peers, preserving both server-driven
population diversity and the proxy's minimum two-way interpretation rule.

The authenticated operator dashboard was inspected against the existing `omalled/polyroute`
project before Polyguard publication. It exposes release/source identity, composition population,
per-function implementation counts, pairwise-risk signals, implementation-relative failure risk,
confidence, status, source links, intervention history, recomposition counts, and an event stream.
It correctly labels controlled simulator failures and preserves a prior quarantine/restore stage.
On first load the telemetry API temporarily fell back to prominently labeled demonstration data;
the same page then refreshed to live project data. Classification pending repetition: transient
service/API availability behavior, not Polyguard evidence. No quarantine or restore control was
activated during reconnaissance. Polyguard-specific findings will be recorded after its own
success and labeled synthetic-failure exercises.

## Generation completion and diversity review

Incremental recovery produced exactly five accepted implementations for every one of the 13
public functions. A second broad batch stopped safely when an authority-generation agent proposed
an existing identity and changed no declared source. The remaining slots were generated one
function at a time, isolating candidate failures. One unledgered header candidate from the earlier
overlapping retry was removed; the shipping registry now has exactly 65 entries. A permanent test
enforces five entries per function, one function per entry, and unique IDs. Every manifest entry
has explicit source provenance. `docs/implementation-diversity.md` records the structural review.

## Real proxy and runtime integration

The executable runs a bounded TCP listener and routes real HTTP/1.1 traffic through typed
multi-implementation agreement for parsing, framing, chunks/trailers, targets, authority,
hop-by-hop removal, routing, forwarding policy, upgrade policy, canonical serialization, and
outcome classification. Raw-TCP tests prove that smuggling cases, oversize bodies, immediate
excess framed bytes, and slow partial requests do not reach a controlled upstream. Chunked
requests are fully validated before connection and canonically forwarded with one content length.
Response heads and chunks are also independently parsed and sanitized.

`polyform vendor-runtime` wrote the official 0.1.0 Rust runtime with source SHA-256
`5f657d18357c574c9d8176f5a35656800e733a044c8469e5f662c71fa383204f`. Polyguard uses a signed
assignment as the primary member of each agreement set and fills remaining slots from local
admitted peers. Refresh failures retain the prior verified assignment. Call telemetry includes
only fixed function IDs, implementation IDs, outcomes, and durations. The runtime's five tests
passed, covering forgery/replay, rollback, inventory/quarantine, restore floors, and metadata-only
telemetry.

## Verification and local environment limits

`polyform check` passed the final format, strict-lint, all-target, fuzz-driver, and differential
gates. A 10,000-case-per-function campaign at seed `20260830` completed without a new saved
counterexample; an independently captured run passed 26,000 cases at seed `9112`. The recorded
percent-encoding disagreement remains a permanent minimized regression and its specification
clarification was made through `polyform resolve --fix-spec`.

Stale evidence was tested safely: `polyform verify` passed, a temporary comment was added to an
evidence-covered README, verification failed with `check evidence is stale`, the comment was
removed, and verification passed again. The signing key was generated with mode 0600 and remains
under ignored `.polyform/` state.

The local environment has no Docker executable and no `cargo audit` subcommand. Classification:
environment capability, not project failure. The repository includes a multi-stage non-root
Dockerfile, a CI container build/smoke job, Dependabot, a locked dependency graph, and strict Cargo
checks. The standalone release artifact is tested directly; final reporting distinguishes local
artifact smoke results from CI container availability.

The optimized executable was copied with only a fresh configuration into a new temporary
directory, started against a controlled loopback Python HTTP server, and successfully proxied a
real HTTP/1.1 request with agreement width three. It then handled `SIGINT` with zero active
connections and exit status zero. The temporary installation and test configuration were removed.
An additional deterministic property suite covers 2,048 generated targets across all request-line
and target implementations plus 1,024 generated duplicate-length framing cases.
