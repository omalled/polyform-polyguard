# Polyguard v0.3.0

Polyguard v0.3.0 expands the strict reverse-proxy core into a practical migration target for
common HTTP/1.1 Nginx deployments while preserving fail-closed interpretation.

## Highlights

- Validate, run, or convert a documented Nginx configuration subset with recursive local
  includes and source-file/line diagnostics for unsupported behavior.
- Serve multiple cleartext and HTTPS listeners from one process, with exact and wildcard SNI
  certificate selection and rejection of SNI/HTTP-authority disagreement.
- Configure typed proxy, redirect, fixed-response, and bounded static-file actions per virtual
  host, path, method, scheme, and source network.
- Serve static indexes and custom 404 pages with MIME types, HEAD, single byte ranges, gzip,
  traversal rejection, and symlink-escape containment.
- Apply bounded response/request headers, forwarding templates, CORS preflight responses,
  HTTP-to-HTTPS redirects, body-limit inheritance, and IPv4/IPv6 access rules.
- Reuse client HTTP/1.1 connections sequentially and report metrics/Polyform telemetry for each
  request rather than each TCP connection.
- Reload routes, upstreams, policies, static roots, compression, and certificates atomically on
  SIGHUP. Invalid reloads retain the working generation and shared aggregate memory bound.
- Deploy with generic systemd and certificate-renewal hook examples.

## Verification

The release gate runs formatting, warning-free strict lints, RustSec audit, 72 normal tests,
13-function deterministic differential fuzzing, an explicit 2,000-request concurrent soak,
Polyform evidence generation, and an optimized build. Compiled-binary integration tests cover the
Nginx import/validation path, real proxy traffic, simultaneous HTTP/HTTPS listeners, multi-SNI
TLS, static gzip/ranges, redirects, CORS, ACLs, prefix rewriting, sequential keep-alive, SIGHUP
reload, invalid-generation retention, body-memory recovery, hostile raw requests, and graceful
shutdown.

## Compatibility boundary

The exact accepted Nginx syntax and semantic substitutions are documented in
`nginx-compatibility.md`. Unknown directives fail validation. Operators should validate the full
top-level configuration and canary the target application before replacing an existing edge.

Polyguard remains HTTP/1.1-only. HTTP/2, HTTP/3, WebSocket tunneling, upstream TLS, DNS upstreams,
load balancing, caching, multi-range responses, authentication modules, rate limiting, regular
expression rewrites/locations, dynamic modules, proxy protocol, and automatic certificate
issuance are not supported. Listener address changes require a restart. Bodies remain bounded in
memory by per-message and shared aggregate limits rather than streamed without buffering.
