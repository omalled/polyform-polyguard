# HTTP protocol policy

Polyguard implements a deliberately strict HTTP/1.1 subset. Normative function-level behavior,
limits, examples, and error precedence are in `specs/polyform.toml`.

## Accepted requests

- Exactly `HTTP/1.1` request lines with one ASCII space between method, target, and version.
- Origin-form and absolute-form for ordinary methods, authority-form for `CONNECT`, and `*` only
  for `OPTIONS` (RFC 9112 §3.2; RFC 9110 §9.3.6).
- Token field names, visible/obs-text values, and edge OWS; field order and duplicates are
  retained until a function with defined combination semantics handles them (RFC 9110 §§5.1–5.6).
- No body, one unambiguous bounded `Content-Length`, or exactly one bare final `chunked` transfer
  coding with strictly parsed chunks and declared bounded trailers (RFC 9112 §§6–7.1).
- One effective authority whose target and `Host` representations agree after default-port
  normalization (RFC 9110 §7.2; RFC 9112 §3.2).

## Rejected requests

- HTTP/1.0, HTTP/0.9, HTTP/2 prefaces, bare line endings, obsolete line folding, controls, NUL,
  whitespace before a field colon, oversized metadata, or ambiguous spacing.
- Conflicting content lengths; invalid decimal members; unsupported, repeated, parameterized, or
  reordered transfer codings; and every `Transfer-Encoding` plus `Content-Length` combination.
- Fragments, raw backslashes/spaces, invalid percent escapes, encoded path slash/backslash,
  traversal above root, userinfo, invalid ports, unbracketed IPv6, and authority/Host mismatch.
- Undeclared, duplicate, or security-sensitive trailer fields.
- Unsupported upgrades and incomplete WebSocket handshakes.
- `Expect: 100-continue` in the first release unless the runtime explicitly implements the
  documented bounded handshake. It is never silently forwarded before a body decision.
- Pipelining on a client connection in the first release. One request is processed per accepted
  connection and both legs use `Connection: close`.

## Canonical upstream form

The upstream request uses uppercase method, normalized origin-form target, one trusted `Host`,
lowercase retained end-to-end header names, reconstructed forwarding fields, exactly one framing
field when needed, and `Connection: close`. Fixed and dynamically nominated hop-by-hop headers are
removed. Canonical output is reparsed during tests to verify the same typed meaning.

## Error handling

Polyguard returns `400 Bad Request` for syntax and framing rejection, `404 Not Found` for no
route, `413 Content Too Large` for body/metadata limits where appropriate, `426 Upgrade Required`
or `400` for unsupported upgrade intent, `502 Bad Gateway` for upstream failures, and `504
Gateway Timeout` for upstream deadlines. A disagreement uses a generic `400` and closes without
exposing implementation details to the client.
