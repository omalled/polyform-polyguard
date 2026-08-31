# Changelog

All notable user-visible changes are documented here. This project follows Semantic Versioning
after the initial experimental release.

## [Unreleased]

## [0.3.2] - 2026-08-30

### Fixed

- Resolve relative `include` directives from the root Nginx configuration prefix, matching Nginx
  behavior for standard layouts where site files include shared root-level parameter files.

## [0.3.1] - 2026-08-30

### Fixed

- Publish a statically linked x86-64 Linux artifact and verify it on an older Linux userspace so
  deployments are not coupled to the GitHub runner's glibc version.

## [0.3.0] - 2026-08-30

### Added

- Fail-closed Nginx configuration validation, direct execution, and native TOML import for a
  documented reverse-proxy, virtual-host, TLS, static-file, redirect, header, access-control,
  body-limit, compression, and CORS subset.
- Multiple cleartext/TLS listeners and multiple exact or wildcard SNI certificates.
- Typed proxy, redirect, fixed-response, and bounded static-file route actions with MIME types,
  indexes, custom error pages, gzip negotiation, and single byte ranges.
- Sequential client HTTP/1.1 keep-alive with per-request metrics and telemetry.
- Atomic SIGHUP configuration and certificate reload with previous-generation retention on error.
- Generic systemd and certificate-renewal hook examples.

### Security

- Reject TLS requests whose supplied SNI name disagrees with the independently reconciled HTTP
  authority.
- Reject unsupported Nginx listener flags and configurations instead of silently approximating
  them.
- Preserve exact-over-wildcard virtual-host precedence and fail closed when socket-specific Nginx
  behavior cannot be represented by authority/scheme routing.
- Apply hard rendered-template limits and shared cross-generation memory accounting to static,
  generated, proxied, and gzip response buffers.
- Reject upstream informational responses rather than treating an interim head as final.

## [0.2.0] - 2026-08-30

### Added

- Native HTTPS termination using Rustls with HTTP/1.1 ALPN and strict certificate/key startup
  validation.
- Separate management listener and saturation-aware readiness.
- Aggregate in-flight body-memory accounting and a reproducible concurrent soak gate.
- Release-time and CI dependency vulnerability auditing.

### Fixed

- Restore accepted sockets to blocking mode so configured partial-request deadlines work on every
  supported platform.
- Move telemetry and composition refresh network operations off request and accept paths.
- Avoid duplicating complete response bodies during canonical serialization.

## [0.1.2] - 2026-08-30

### Fixed

- Restrict hosted per-call telemetry to invoked members that are active in the signed server
  composition, while keeping additional local agreement peers in the fail-closed execution set.

## [0.1.1] - 2026-08-30

### Fixed

- Map per-call runtime telemetry to the hosted API's documented bounded outcome vocabulary so
  successful requests, ordinary failures, and disagreement-classified executions are accepted.

## [0.1.0] - 2026-08-30

### Added

- Security-first HTTP/1.1 reverse proxy foundation.
- Polyform specification and independently generated protocol/policy implementation registry.
- Differential conformance, fuzzing, integration, and release-evidence workflows.
- Privacy-bounded telemetry and implementation quarantine/remediation procedure.
