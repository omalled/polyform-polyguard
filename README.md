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

The executable supports native HTTPS with Rustls, multiple listeners and SNI certificates,
multiple named upstreams, typed proxy/redirect/response/static actions, virtual hosts,
boundary-aware longest-path routing, gzip and byte ranges, explicit limits and deadlines,
sequential HTTP/1.1 keep-alive, atomic configuration/certificate reload, health/readiness
endpoints, graceful shutdown, structured diagnostics, and privacy-safe outcome metrics.

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

To evaluate an existing Nginx deployment, validate the complete configuration before starting:

```sh
polyguard --check-nginx /etc/nginx/nginx.conf
polyguard --nginx-config /etc/nginx/nginx.conf
```

The importer expands local includes and fails with file-and-line diagnostics when behavior is not
in the [supported Nginx subset](docs/nginx-compatibility.md). `--import-nginx` prints equivalent
native TOML for review. `polyguard.multi-site.example.toml` demonstrates multiple HTTP/HTTPS
virtual hosts and SNI certificates without relying on the importer.

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
[implementation diversity review](docs/implementation-diversity.md). The
[v0.3.0 production-readiness assessment](docs/production-readiness-v0.3.0.md) states the current
deployment envelope; the [v0.2.0 assessment](docs/production-readiness-v0.2.0.md) remains as
historical evidence. The complete deterministic contract with
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
[v0.3.0 GitHub release](https://github.com/omalled/polyform-polyguard/releases/tag/v0.3.0), and
the live project is on the [Polyform dashboard](https://omalled.com/polyform/omalled/polyguard/dashboard).

## Current restrictions

Polyguard is intentionally HTTP/1.1-only. It does not approximate HTTP/2, HTTP/3,
close-delimited request bodies, unsupported transfer codings, client pipelining, or incomplete
upgrades. Clients may reuse a connection sequentially; canonical upstream connections remain
one request each with explicit framing. WebSocket tunnels, upstream TLS, load balancing, caching,
and automatic certificate issuance remain unsupported. Consult the compatibility document and
release notes before exposing a listener to untrusted networks.
