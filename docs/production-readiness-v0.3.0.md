# Polyguard v0.3.0 production-readiness assessment

## Verdict

Polyguard v0.3.0 is suitable for a controlled production deployment when the required behavior is
inside its documented HTTP/1.1 and Nginx-compatibility envelope. It should not be treated as a
general drop-in replacement for every Nginx module or protocol.

The minimum safe rollout is: validate the complete configuration, run application-specific HTTP
and HTTPS tests, keep the previous edge available for rollback, canary traffic, protect the
management listener, run as an unprivileged service, and monitor rejection, disagreement,
upstream-failure, timeout, saturation, and telemetry-drop counters.

## Verified controls

- Three-way agreement is exercised in integration tests; production defaults require at least two
  independently registered implementations for every critical interpretation function.
- Ambiguous request framing, malformed chunks/trailers, target/authority disagreement, nominated
  hop-by-hop fields, pipelined bytes, and implementation disagreement are rejected before an
  upstream request is written.
- Certificate/key matching, exact and wildcard SNI selection, HTTP/1.1 ALPN, forwarding scheme,
  simultaneous HTTP/HTTPS listeners, and SNI/Host agreement are tested with real TLS connections.
- Per-message and cross-generation aggregate body-memory limits, connection limits, header/body
  deadlines, response bounds, overload readiness, and recovery are tested.
- Static roots use canonical containment checks and reject normalized traversal and symlink escape;
  file size remains bounded before reading.
- SIGHUP builds and validates a complete generation before activation. Active connections retain
  the old generation, invalid input retains it globally, and unchanged Polyform registration plus
  aggregate memory accounting are shared across generations.
- Metrics and hosted telemetry use fixed operational categories and implementation IDs without
  request targets, authorities, headers, bodies, credentials, or raw client addresses.

## Operating constraints

Use cleartext upstream HTTP only on a protected network. Use explicit body and response limits
appropriate for the application; buffering is bounded but can still create memory pressure if set
too high. Static roots and configuration files must be writable only by trusted deployment
principals. TLS keys are unencrypted PEM files and require filesystem protection.

Client keep-alive is sequential, not pipelined. Upstream connections are not pooled. The worker
model is one bounded thread per admitted client connection. WebSocket upgrades are rejected.
Certificate issuance is external; the supplied deploy hook validates and reloads renewed files.
Listener and management socket addresses cannot change on SIGHUP.

The full release gate includes strict linting, all-target tests, dependency audit, deterministic
differential fuzzing across all 13 functions, a 2,000-request concurrent soak, and an optimized
build. Publication-specific artifact checksums, signature/evidence results, clean-install traffic,
and hosted composition observations are recorded in the lifecycle log after publication.
