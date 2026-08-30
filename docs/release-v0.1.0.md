# Polyguard v0.1.0 release notes

Status: draft until the signed/tagged GitHub release and Polyform publication are both verified.

## What ships

Polyguard v0.1.0 is one Rust executable implementing a bounded HTTP/1.1 reverse proxy. Its
security-critical interpretation and policy functions are supplied through a Polyform registry
with exactly five independently generated, admitted implementations per function. Production
agreement mode executes at least two selected implementations on identical inputs and fails
closed on any typed-result or byte-boundary disagreement before an upstream write.

The release includes configuration validation, exact-host and longest-prefix routing, canonical
upstream request serialization, strict request framing, bounded chunk/trailer handling, forwarding
metadata reconstruction, hop-by-hop removal, connection and byte limits, per-stage timeouts,
structured privacy-safe diagnostics, health/readiness/metrics endpoints, and graceful shutdown.

## Deliberate restrictions

- Cleartext HTTP/1.1 only; terminate TLS at a maintained edge proxy.
- HTTP/2 and HTTP/3 are rejected rather than approximated.
- WebSocket upgrade metadata is interpreted but tunneling is not enabled in v0.1.0.
- Unsupported transfer codings and close-delimited request bodies are rejected.
- One request per client/upstream connection; canonical requests use `Connection: close`.
- No caching, load balancing, or retry after request bytes are written. Responses are bounded,
  stripped of hop-by-hop metadata, and reserialized with one explicit length.

## Verification evidence

The final release replaces these pending entries with immutable values:

- source commit: **pending**
- GitHub release URL: **pending**
- Polyform project/release URL: **pending**
- Polyform release identity: **pending**
- executable SHA-256: **pending**
- manifest SHA-256: **pending**
- Rust toolchain: **pending**
- Polyform CLI checksum/version: **pending**
- conformance, integration, raw-TCP, fuzz, lint, audit, and clean-install results: **pending**

The executable manifest enumerates function-to-implementation provenance. Publication evidence,
composition exercises, telemetry exercises, dashboard investigation, and remediation findings are
also recorded in `docs/polyform-lifecycle.md`.
