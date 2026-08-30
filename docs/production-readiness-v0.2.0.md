# Polyguard v0.2.0 production-readiness assessment

## Verdict

Polyguard v0.2.0 is ready for a controlled production deployment of its documented strict
HTTP/1.1 reverse-proxy subset. The assessment covers the signed source, both downloadable
executables, native HTTPS, the container build, clean installation, real proxy traffic, bounded
overload behavior, dependency audit, and the active Polyform composition/dashboard path.

Production use must stay within the documented envelope: HTTP/1.1 clients, HTTP/1.1 cleartext
upstreams on a protected network, explicit certificate management, agreement width of at least
two, bounded request/response sizes, and a protected management listener. Start with a canary,
monitor readiness and disagreement/drop counters, and retain a known-good edge rollback.

## Evidence

- Source/tag commit: `420880d9e71e9819f9a42031b51ff695c33b7943`
- Signed Polyform release: release 6, version 0.2.0
- GitHub CI: formatter, strict lints, RustSec audit, all-target tests, optimized Linux build,
  container build, and container executable smoke passed.
- Local release gate: 55 normal tests, 2,000-request concurrent soak, differential fuzzing across
  all 13 functions, current Polyform evidence, and optimized build passed.
- Native TLS: Rustls certificate/key validation, hostname validation, HTTP/1.1 ALPN, HTTPS proxying,
  forwarding metadata, and graceful `close_notify` behavior are exercised by tests.
- Clean install: `polyform install` verified the release signature/evidence and installed a binary
  whose SHA-256 matched the public asset; that binary proxied a real HTTPS request successfully.
- Resource behavior: per-message and aggregate body limits, connection cap, slow/partial input,
  saturation readiness, queue overflow accounting, and post-overload recovery are tested.
- Dashboard: the active v0.2 release has no investigated or quarantined implementation; a signed
  balanced installation registered and received a valid composition.

Artifact hashes and the detailed commands, discrepancies, workarounds, lifecycle experiments, and
dashboard residue are recorded in `docs/polyform-lifecycle.md`.

## Deliberate limitations

Polyguard does not support HTTP/2, HTTP/3, WebSocket tunneling, client pipelining, keep-alive
connection reuse, upstream TLS, dynamic certificate reload, automatic certificate issuance,
retries, caching, load balancing, or zero-downtime configuration reload. Unsupported or ambiguous
protocol behavior is rejected rather than approximated. The management listener is cleartext and
must be bound to loopback or a protected management network.

TLS private keys must be unencrypted PEM because the current executable has no interactive secret
provider. Certificate renewal requires a graceful process restart. The proxy uses one bounded
thread per admitted connection; the default cap is 128 and the configured hard maximum is 1,024.
These are explicit operating constraints, not claims of feature parity with a mature general-purpose
edge proxy.
