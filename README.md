# Polyguard

Polyguard is a security-first HTTP/1.1 reverse proxy written in Rust. Its protocol and policy
core is generated through Polyform: multiple independently structured implementations interpret
the same bounded request metadata, and the default agreement mode rejects and closes before
upstream bytes are written if their typed results differ.

```text
client → TLS/HTTP/1.1 → Polyguard → HTTP/1.1 application servers
```

## Quick start

Copy the safe local example and point its upstream at an application server:

```sh
cp polyguard.example.toml polyguard.toml
cargo run --release --bin polyguard -- --config polyguard.toml
curl --http1.1 -H 'Host: example.test' http://127.0.0.1:8080/
```

The executable supports native HTTPS with Rustls, one process, multiple named upstreams, exact-host and
boundary-aware longest-path routing, explicit limits and deadlines, health/readiness endpoints,
graceful shutdown, structured diagnostics, and privacy-safe outcome metrics. The release notes
identify any feature (notably WebSocket tunneling) that remains deliberately
unsupported and is therefore rejected.

For a local HTTPS check, create a disposable certificate, update the paths and host in
`polyguard.https.example.toml`, and start Polyguard:

```sh
mkdir -p .local-tls
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
  -keyout .local-tls/private-key.pem -out .local-tls/fullchain.pem \
  -subj '/CN=example.test' -addext 'subjectAltName=DNS:example.test'
cargo run --release --bin polyguard -- --config polyguard.https.example.toml
curl --cacert .local-tls/fullchain.pem --resolve example.test:8443:127.0.0.1 \
  https://example.test:8443/
```

The HTTPS example uses production-oriented connection and aggregate body-memory limits. Replace
the disposable certificate with an automatically renewed certificate before deployment.

## Security behavior

The safest outcome wins over compatibility:

- HTTP/1.1 request-line and header grammar is strict.
- `Transfer-Encoding` plus `Content-Length`, conflicting lengths, invalid transfer codings,
  malformed chunks, authority disagreement, and implementation disagreement never reach upstream.
- Hop-by-hop metadata is removed and trusted forwarding fields are reconstructed.
- Request and response data is bounded and subject to timeouts.
- Polyform telemetry contains fixed operational categories, not request content.

See [architecture](docs/architecture.md), [threat model](docs/threat-model.md),
[protocol policy](docs/protocol-policy.md), [telemetry privacy](docs/telemetry-privacy.md), and the
[operator guide](docs/operator-guide.md), plus the
[Polyform lifecycle log](docs/polyform-lifecycle.md) and
[implementation diversity review](docs/implementation-diversity.md). The complete deterministic contract with
standards citations and adversarial examples is [the Polyform specification](specs/polyform.toml).

## Development verification

```sh
cargo fmt -- --check
cargo clippy --all-targets --locked -- -D warnings
cargo test --all-targets --locked
./scripts/release-check.sh
```

To use a published Polyform composition, add a `[polyform]` section as documented in the operator
guide. The signed server assignment chooses the primary implementation for each function;
Polyguard still executes the configured number of independent local peers and rejects disagreement.

Fuzz seeds, raw-TCP tests, local upstream integration tests, clean-install checks, release
checksums, publication URLs, and the labeled quarantine/restore experiment are recorded in the
[lifecycle log](docs/polyform-lifecycle.md). The public artifacts are in the
[v0.2.0 GitHub release](https://github.com/omalled/polyform-polyguard/releases/tag/v0.2.0), and
the live project is on the [Polyform dashboard](https://omalled.com/polyform/omalled/polyguard/dashboard).

## Current restrictions

Polyguard is intentionally HTTP/1.1-only. It does not approximate HTTP/2, close-delimited
request bodies, unsupported transfer codings, ambiguous pipelining, or incomplete upgrades.
Connection reuse is not required for v0.2.0; canonical requests use `Connection: close` to keep
boundaries explicit. Consult the release notes before exposing a listener to untrusted networks.
