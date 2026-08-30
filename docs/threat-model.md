# Threat model

## Assets and security objectives

Polyguard protects the upstream application's HTTP message boundary, routing decision, authority,
and forwarding identity. Its primary objective is that ambiguous or malformed client input never
becomes upstream request bytes. Secondary objectives are bounded resource use, privacy-safe
operations, deterministic routing, and fail-closed behavior when independent interpretations
disagree.

## Adversaries

The model includes unauthenticated network clients able to send arbitrary bytes slowly or in
bursts, pipeline bytes, close prematurely, and exploit differences between HTTP implementations.
It also includes clients spoofing forwarding metadata and upstream servers returning malformed,
oversized, slow, or partial responses. Operators and the host are trusted; compromised upstream
applications, operating systems, TLS libraries, or signing keys are outside this release's
protection boundary.

## Addressed attacks

- Request smuggling through conflicting or repeated `Content-Length`, invalid
  `Transfer-Encoding`, or both fields together (RFC 9112 §§6.2–6.3).
- Parser disagreement from whitespace before a colon, obsolete folding, bare CR/LF, NUL,
  controls, duplicate `Host`, or inconsistent absolute-form authority (RFC 9110 §§5.1–5.5,
  7.2; RFC 9112 §§2.2, 3, 6.3).
- Hidden routing differences through dot segments, malformed percent escapes, encoded path
  separators, fragments, or authority confusion (RFC 3986 §§2.1–2.2, 3.2–3.3, 5.2.4).
- Hop-by-hop leakage, including fields nominated by `Connection` (RFC 9110 §7.6.1).
- Forwarding identity spoofing across an untrusted listener boundary (RFC 7239 §§4–7).
- Upgrade confusion and incomplete WebSocket handshakes (RFC 6455 §§4.1, 4.2.1, 11.3).
- Slow clients, oversized metadata and bodies, premature EOF, and upstream stalls through
  explicit limits, aggregate memory accounting, deadlines, and concurrency controls.
- Passive network observation and modification on the client-facing hop when native TLS is
  configured; certificate issuance, DNS control, private-key custody, and endpoint compromise
  remain operator responsibilities.
- Silent generated-code regression through shared conformance, differential, fuzz, raw-TCP,
  integration, and release-evidence gates.

## Fail-closed rules

Malformed or ambiguous requests receive a suitable 4xx response when doing so is safe, followed
by connection closure. Any critical implementation disagreement is classified with a fixed
privacy-safe code, never reaches upstream, and closes the client connection. A partial upstream
response cannot be replaced with a clean error; Polyguard closes both directions and records an
upstream failure category.

## Residual risk

Independent code generation reduces common parser defects but does not prove correctness.
Implementations share the specification, Rust compiler, public models, process, and test corpus.
A specification defect may affect every variant. Agreement also increases CPU work and attack
surface. Resource bounds, diverse decompositions, property tests, fuzzing, and operational
quarantine reduce—but do not eliminate—these risks.

The initial release explicitly rejects unsupported protocol features instead of approximating
them. TLS and WebSocket tunneling are shipped only if end-to-end tests establish safe behavior;
otherwise their intent is detected and rejected.
