# Polyguard v0.2.0 release notes

Status: release candidate until signed Polyform publication, downloadable artifacts, clean
installation, HTTPS smoke testing, and GitHub release verification are complete.

## Production hardening

- Native HTTPS termination uses Rustls with safe protocol/cipher defaults, HTTP/1.1 ALPN,
  certificate-chain and private-key validation, disabled early data, and TLS `close_notify`.
- A separate optional management listener prevents health, readiness, and metrics paths from
  occupying or leaking through application route space.
- Readiness reports saturation instead of returning a static success response.
- Aggregate request/response body-memory accounting bounds concurrent allocations and returns
  503 before exceeding the configured budget.
- The connection cap default is reduced to 128 and the accepted maximum is 1,024.
- Accepted sockets are explicitly restored to blocking mode. This fixes a platform-dependent bug
  where partial bodies could receive immediate timeouts rather than the configured deadline.
- Hosted telemetry is sent through a bounded asynchronous queue. Composition refresh also runs
  off the accept loop, preventing hosted-service latency from blocking new connections.
- Response serialization no longer duplicates a complete buffered response body.
- Dependency auditing is a release and CI gate. The first audit identified the unmaintained
  `rustls-pemfile` helper; v0.2.0 uses maintained `rustls-pki-types` PEM support and audits cleanly.

## Compatibility

Cleartext HTTP remains available when `[listener.tls]` is absent. Native TLS is configured with
`certificate_chain_file` and `private_key_file`. Management endpoints are disabled unless
`listener.management_address` is set. The 13 Polyform functions, 65 implementation identities,
typed agreement semantics, HTTP/1.1 rejection policy, and telemetry privacy schema are unchanged.

WebSocket tunneling, HTTP/2, client/upstream connection reuse, retries, caching, and built-in
certificate issuance remain deliberately unsupported.
