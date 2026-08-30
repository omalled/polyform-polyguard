# Changelog

All notable user-visible changes are documented here. This project follows Semantic Versioning
after the initial experimental release.

## [Unreleased]

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
