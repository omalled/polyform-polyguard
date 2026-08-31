# Polyform lifecycle log

This log distinguishes documented behavior from local workarounds. The release, runtime,
telemetry, dashboard, and remediation results below were finalized on 2026-08-30.

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

The authenticated operator dashboard was first inspected against the existing
`omalled/polyroute` project before Polyguard publication. It exposes release/source identity, composition population,
per-function implementation counts, pairwise-risk signals, implementation-relative failure risk,
confidence, status, source links, intervention history, recomposition counts, and an event stream.
It correctly labels controlled simulator failures and preserves a prior quarantine/restore stage.
On first load the telemetry API temporarily fell back to prominently labeled demonstration data;
the same page then refreshed to live project data. Classification pending repetition: transient
service/API availability behavior, not Polyguard evidence. No quarantine or restore control was
activated during reconnaissance.

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

During the v0.1 assessment the local environment had no Docker executable or `cargo audit`
subcommand. Classification: environment capability, not project failure. For v0.2, `cargo-audit`
0.22.2 was installed and made a local, Polyform-evidence, release, and CI gate. The local host still
has no Docker executable, but GitHub Actions built the multi-stage non-root image and ran its
executable smoke test successfully on the exact release source.

The optimized executable was copied with only a fresh configuration into a new temporary
directory, started against a controlled loopback Python HTTP server, and successfully proxied a
real HTTP/1.1 request with agreement width three. It then handled `SIGINT` with zero active
connections and exit status zero. The temporary installation and test configuration were removed.
An additional deterministic property suite covers 2,048 generated targets across all request-line
and target implementations plus 1,024 generated duplicate-length framing cases.

## Publication, clean install, and live telemetry

The public project is `https://omalled.com/polyform/omalled/polyguard`; the public source is
`https://github.com/omalled/polyform-polyguard`. GitHub Actions passed for release source commit
`bd45c720ffe72054518df58a11e9bdab8d7791c1`. Polyform published that exact source and evidence as
release 5 / version 0.1.2. GitHub release `v0.1.2` contains the executable, signed manifest,
Polyform evidence, and checksum file. The final hashes are:

- executable: `ab5d5e08e9ba2c867fd7dabc66c638c4fada873d3f8f1afbb67743d9968401fd`
- manifest: `6d945018299d9cbe37b2565ee2cfff08017c8cfc1e32e0baa69e32dc2cccccec`
- evidence: `1fd2107401979e03287bd629df81f92c056106f4476b7be4ee61179bf5acfefd`

A clean `polyform install --version 0.1.2` produced an artifact matching the executable hash and a
trust file bound to application `omalled/polyguard`, release 5, and version 0.1.2. Three distinct
clean installations registered with `balanced`, `random`, and `homogeneous` strategies. Each
proxied a real routed request as HTTP 200 and rejected an ordinary missing route as HTTP 404; all
six executions reached hosted telemetry without reporting errors. The documented `stable`
strategy was not used because the live registration API returned HTTP 422 and enumerated only
`balanced`, `random`, and `homogeneous`.

Live integration found and fixed two runtime/API contract mismatches before v0.1.2. First, the
vendored client accepted `success`, `failure`, and `disagreement`, while the hosted endpoint
accepted only `ok`, `error`, `timeout`, and `panic`; an isolated official-runtime request produced
HTTP 422 and then succeeded after correction. Second, the endpoint rejects telemetry for locally
invoked agreement peers not active in the signed server composition. Polyguard now truthfully
reports only invoked server-active calls while retaining all local peer execution and fail-closed
agreement behavior. Both defects have permanent regression tests. The CLI/runtime currently has
no discovery or version-negotiation endpoint for these schemas; that is a platform integration
risk rather than a proxy-protocol defect.

## Labeled disagreement and reversible intervention

No genuine implementation fault was found. A metadata-only isolated experiment therefore
submitted explicitly labeled synthetic disagreement executions—never production traffic or user
content—against implementation `upgrade-observation-policy-table` (`UOPT`). Thirty failures made
the dashboard mark UOPT `Investigate` at 9.9x relative risk and 100% corrected confidence. The
earlier five-event probe against `chunk-metadata-guarded-parts` remained below the confidence
threshold and was not quarantined.

The dashboard quarantine preview identified one affected client. Quarantine moved UOPT out of
circulation; the client checked in at list version 2 / composition revision 2 and changed its
`decide_upgrade` assignment to `upgrade-transformation-matrix`. The dashboard verified 1/1 clients
recomposed. Ten explicitly labeled synthetic healthy controls then measured 100% healthy after
quarantine versus the intentionally failure-heavy 7.3% synthetic baseline (+92.7 percentage
points). This is experiment evidence, not a claim about real-world defect remediation.

Restore returned UOPT to circulation for future assignments while correctly preserving the
existing healthy replacement composition. A final check-in advanced the implementation list to
version 3, retained revision 2, reported UOPT `active`, and reported no quarantined identities.
The dashboard retains the intervention history and the synthetic risk signal; UOPT therefore
remains advisory `Investigate`, not quarantined. The current web dashboard supports preview,
quarantine, automatic recomposition, restoration, before/after measurement, and audit history.
The installed CLI exposes none of those operator mutations, does not require a reason field in the
web flow, and does not provide evidence-bundle reproduction or repair/replace commands; the target
workflow in `docs/remediation-workflow-proposal.md` records those remaining product gaps.

## v0.2 production hardening and publication

The post-v0.1.2 review found production-readiness gaps in TLS termination, aggregate memory
accounting, telemetry/service latency isolation, management endpoint isolation, saturation-aware
readiness, default connection limits, and release dependency auditing. Release 0.2.0 addresses
those gaps with Rustls HTTPS, an aggregate request/response body budget, bounded asynchronous
telemetry, background composition refresh, a separate optional management listener, explicit
readiness capacity checks, lower connection limits, and an advisory audit gate. A platform-specific
accepted-socket blocking-mode defect found by the overload test was also fixed permanently.

The complete local release gate passed formatting, strict locked lints, RustSec audit against
1,226 advisories, 55 normal tests, a 2,000-request concurrent soak, 13-function differential
fuzzing, Polyform evidence generation/verification, and an optimized build. Native HTTPS was
tested end to end with certificate hostname validation and HTTP/1.1 ALPN. GitHub Actions run
`33337060059` independently passed the same source's Linux verification plus a real container
build/smoke test. Release-artifact run `33337119380` independently audited, tested, and built the
Linux binary before upload.

The exact release source is commit `420880d9e71e9819f9a42031b51ff695c33b7943`. Polyform published
it as release 6 / version 0.2.0. GitHub published tag `v0.2.0` with these verified SHA-256 values:

- macOS ARM64 executable: `8a778a5376a20a8eeba86ed57ebfe7ddb88b61f96db08ee9f64dbb14823ac751`
- Linux x86-64 executable: `96ecd72c2262ba120fe0fa147e2bae59635c046ecd4c7ddbc758d6f45cc4725a`
- implementation manifest: `4a49e674d4b88601a828b5746682189f7a8bedffceeb0b07a63a436e8e22c922`
- Polyform evidence: `19bca84b86a7c24f3ac2477c577a0a895484fbc0fb10d6026aba29aa10a68cda`
- portable unified checksum file: `ac3d10395261d42bd54eef560b059c0e5239346b0481a6b8f1c10164c9b1039e`

A second clean `polyform install --version 0.2.0` cryptographically verified release 6, produced a
binary matching the macOS checksum, and wrote trust metadata bound to `omalled/polyguard`, release
6, and version 0.2.0. With only a fresh configuration and disposable local certificate, that exact
installed binary proxied a real HTTPS request to a controlled HTTP upstream, returned healthy and
ready management status, reported zero disagreements/drops/failures with body memory returned to
zero, and shut down gracefully with zero active connections.

The public update path was exercised independently: a new temporary location first installed and
verified v0.1.2 / release 5 with executable hash
`ab5d5e08e9ba2c867fd7dabc66c638c4fada873d3f8f1afbb67743d9968401fd`; `polyform update
omalled/polyguard --version 0.2.0` then atomically replaced it with release 6. The resulting help
identified version 0.2.0, its executable matched the published v0.2.0 macOS hash, and the trust
metadata advanced from release 5/version 0.1.2 to release 6/version 0.2.0.

The first generated `SHA256SUMS` asset used build-directory prefixes and predated the asynchronous
Linux upload. The asset was replaced with a portable basename-only list covering both executables,
the manifest, and evidence; an independent clean download verified all four entries. The release
workflow was then corrected to generate that unified file automatically. Classification: release
packaging defect found and repaired before final reporting; published binaries were unchanged.

The active v0.2 dashboard shows the correct release/source identity, 13 functions, 65
implementations, 1.2 billion possible compositions, no quarantined implementations, and no active
`Investigate` rows. An append-only false-positive resolution was recorded for UOPT while the page
still showed the old synthetic experiment. On refresh, the dashboard switched to release 6 and the
remaining v0.1.2 synthetic/exposure alerts became historical rather than active/actionable; the
service exposes no release selector for adding resolution events to those old rows. A verified
v0.2 installation then registered successfully with a signed balanced composition and proxied ten
healthy HTTPS requests without local telemetry errors or dropped events. The synthetic installation
identifier and runtime state remained only in ignored temporary state and were deleted after the
test; no private installation data entered the repository.

The accepted v0.2 execution reports had not appeared in the dashboard by the final repeated refresh:
the active composition and client were visible, but the page still showed zero telemetry events and
zero per-implementation executions. The proxy logged no hosted-report failures, its bounded queue
reported zero drops, and the same hosted execution path was visibly proven during the v0.1.2
lifecycle, so this is classified as a Polyform ingestion/dashboard freshness discrepancy rather
than a Polyguard data-plane failure. Operators should not rely on the hosted dashboard as their
only immediate v0.2 health signal; local readiness, counters, and structured logs remain required.

## v0.3 Nginx migration release and publication

Release 0.3.0 adds the fail-closed Nginx validation/import path, multiple HTTP and HTTPS listeners,
exact and wildcard SNI certificates, deterministic typed actions, bounded static serving and gzip,
sequential HTTP/1.1 keep-alive, and atomic SIGHUP reload. The local release gate passed 72 normal
tests, strict warning-free lints, RustSec audit, a 2,000-request concurrent soak, deterministic
differential fuzzing, Polyform evidence generation and verification, and an optimized build.

The exact release source is commit `4bfde969c6e853e914b7f5d1c19f05fdd1fee57f`. GitHub release
`v0.3.0` is pinned to that commit. Release-artifact workflow run `33344195057` independently passed
the locked RustSec audit, all-target test suite, optimized Linux build, packaging, and asset upload.
The published SHA-256 values are:

- macOS ARM64 executable: `fb3c2aef56e66c396e484ca3b8e13550e18746d95f5c2e340716e90e0e8143de`
- Linux x86-64 executable: `00852e803496e2f4ade1e3aae9f86e7661ef018773d53a18dffe608af0c3fbcd`
- implementation manifest: `db1c6e4564e1aa4c4901d4003cf832b60f6054af94edf03ded5b0d82dad73247`
- Polyform evidence: `8b13209430c3e4803b548cb6fef34bfee8c86e2c07330cab08e2a0d135292cdc`
- portable unified checksum file: `bcacf1705a2982494a8781a02b9022856e73d7964fcedab1c73adbbda46ea4d5`

An independent clean download verified every entry in `SHA256SUMS`; the downloaded manifest and
evidence were byte-identical to the locally verified inputs. Polyform published the same artifact
and evidence as release 7 / version 0.3.0. A fresh `polyform install --version 0.3.0`
cryptographically verified release 7, produced the published macOS checksum, and wrote trust
metadata bound to `omalled/polyguard`, release 7, and version 0.3.0.

The freshly installed binary registered with a signed balanced composition and served eleven real
HTTPS requests through a disposable `app.example.test` certificate and controlled loopback HTTP
upstream. Certificate hostname validation, SNI routing, HTTP/1.1 ALPN, an HSTS response header,
health/readiness isolation, and graceful shutdown all passed. Final local counters reported eleven
accepted requests, zero rejections, disagreements, upstream failures, timeouts, or telemetry drops,
and zero active connections or retained body bytes.

The authenticated dashboard identified 0.3.0 as the active release, linked every implementation to
the exact release commit, showed one active client and 100% healthy execution, and reflected the
clean-install calls as zero-failure direct-call implementation executions. Its top-level telemetry
event stream remained at zero because that stream is restricted to hard failures and composition
changes; the per-implementation execution table was current and supplied the successful-call
evidence that had been missing during the v0.2 observation.

## v0.3.5 bounded expectation repair and publication

Release 0.3.5 adds bounded client-side `Expect: 100-continue` handling, checks declared body limits
before route actions or interim responses, and preserves Nginx missing-static-resource precedence.
The changes are confined to the proxy coordinator; no typed Polyform function contract or
independent implementation changed. The complete local release gate passed 77 normal tests, the
2,000-request soak, strict warning-free lints, the RustSec audit, differential fuzzing, evidence
generation/verification, and an optimized build. A controlled loopback regression confirmed
matching status behavior for oversized, missing, existing-static, and proxied expectation cases.

The exact release source is commit `5f98f679cbdf6574b81ee997c0d8f5d417cbdfe2`. GitHub Actions run
`33349535598` passed source verification, container smoke, portable static Linux construction, and
an older-userspace smoke test. Release-artifact run `33349649631` independently audited, tested,
built, smoke-tested, checksummed, and uploaded the artifacts. GitHub release `v0.3.5` and Polyform
release 12 / version 0.3.5 publish that same source and evidence. An independent clean download
verified the unified checksum set:

- macOS ARM64 executable: `c029149e7e9d672d59b324636a7e1504537e3f321ca3dc6104338aa50c56ce46`
- GNU Linux x86-64 executable: `457b80a4bd6248ec6dc1482eb633e365b78a5736f428adc5953842afb1f9ff78`
- static Linux x86-64 executable: `5e66141fd76f8c44970fded2749b468cfe23d93ed771ac02b581dabc3ab31617`
- implementation manifest: `9024a116fe3ff630c26e56b5f947642c7ff0958b6da78f092e8ffb8c8f76fa5a`
- Polyform evidence: `c88a35b7ba1edcb51e5f20f6c104f77b59ea95e17f5cf2e95ab8a525de5dbfa8`
- portable unified checksum file: `611e8423ee8e07bba324991e8a131bb9aba0a5f36e3a4b11140983dbfe0fbbe0`
