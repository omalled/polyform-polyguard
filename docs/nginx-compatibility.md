# Nginx configuration compatibility

Polyguard can validate and run a security-focused subset of an existing Nginx configuration:

```sh
polyguard --check-nginx /etc/nginx/nginx.conf
polyguard --nginx-config /etc/nginx/nginx.conf
```

`--import-nginx` prints the equivalent native TOML configuration. The importer expands local
`include` directives, reports unsupported directives with their source file and line, and refuses
to start if any parsed behavior cannot be represented safely. It never silently treats an
unknown directive as compatible.

## Supported subset

| Nginx feature | Polyguard behavior |
| --- | --- |
| `events`, common worker/logging/socket tuning | Accepted as operational settings; Polyguard uses its own bounded worker model |
| Multiple `listen` addresses | One process listens on every distinct cleartext or TLS socket |
| `ssl`, `default_server`, `ipv6only=on` | Supported; HTTP/2 and proxy-protocol flags are rejected |
| Multiple TLS virtual servers | Certificate/key pairs are validated before binding and selected by exact or `*.` SNI name |
| `server_name` | Exact names, `*.` wildcards, and `_` default servers |
| Exact, prefix, and `^~` locations | Deterministic host/path matching; regular-expression locations are rejected |
| `proxy_pass http://IP:PORT[/path/]` | Cleartext HTTP/1.1 upstream with Nginx-compatible prefix replacement |
| `proxy_set_header` | Safe literal/template headers; forwarding and hop-by-hop fields remain security-managed |
| `root`, `alias`, `index`, `try_files $uri $uri/ =404` | Bounded static files with traversal and symlink-escape checks, MIME types, indexes, HEAD, and single byte ranges |
| `return` | Fixed responses and 301/302/303/307/308 redirects with bounded safe templates |
| `add_header` and `always` | Response headers with Nginx inheritance at server/location scope |
| `if ($host = ...)` | Host-specific `return`, including HTTP-to-HTTPS redirects |
| `if ($request_method = ...)` | Method-specific `return` and `add_header`, including CORS preflight responses |
| `deny` | IPv4/IPv6 addresses, CIDRs, and `all` |
| `client_max_body_size` | HTTP, server, and location inheritance, up to Polyguard's 16 MiB hard request-body bound |
| `gzip`, `gzip_types` | Bounded gzip for configured content types when the client advertises support |
| Certbot TLS option includes | Common TLS protocol, cipher, session, ticket, and DH-parameter directives are accepted; Rustls applies its maintained TLS policy |

The parser also accepts common `http`-level MIME, logging, sendfile, TCP, keep-alive, and TLS
configuration directives whose operational effect is supplied by Polyguard rather than copied
verbatim.

Routes are selected by authority and scheme rather than local socket address. Duplicate IPv4/IPv6
listeners with identical behavior are deduplicated; conflicting behavior for the same server name
and scheme on different sockets is rejected during import.

## Deliberately unsupported

Polyguard rejects configuration that depends on HTTP/2 or HTTP/3, stream/mail blocks, upstream
groups or load-balancing directives, DNS names in `proxy_pass`, FastCGI/uwsgi/gRPC, regular
expression rewrites or locations, authentication modules, caching, rate limiting, WebSocket
tunnels, dynamic modules, `proxy_protocol`, multi-range responses, or automatic certificate
issuance. It also rejects unknown directives and unsafe overrides of framing, connection, client
identity, or forwarding metadata.

Nginx permits modules to add arbitrary syntax, so compatibility is intentionally established by
running `--check-nginx` against the complete top-level configuration, not by assuming a site file
is portable. Keep Nginx installed until application, TLS, static-file, reload, and failure-path
tests pass in the target environment.

## Reload and certificate rotation

`SIGHUP` reparses the original Nginx file and all includes, validates routes, static roots, and
every TLS certificate/key pair, builds the new runtime, and swaps it in as one generation. Active
connections finish on the old generation. A failed reload logs a bounded failure record and keeps
the previous generation.

The set of listener addresses cannot change during reload; restart the service for socket
additions or removals. Certificate contents, virtual hosts, routes, headers, access rules, body
limits, static roots, compression settings, and upstream addresses can change without restarting.

Before reloading manually:

```sh
polyguard --check-nginx /etc/nginx/nginx.conf
systemctl reload polyguard
```

The example Certbot deploy hook in `packaging/certbot-deploy-hook.sh` performs the same check before
requesting a reload. The systemd unit repeats validation as the unprivileged `polyguard` account
before signaling the running process, so renewal fails safely if that account cannot read a new
key. Grant only that account (or a dedicated certificate-reader group) read access to deployed
private keys; do not make keys world-readable.

The packaged service exposes `/home` read-only for imported static roots. If the Nginx master
currently relies on root-only certificate access, grant the unprivileged Polyguard account narrow
reader access through a dedicated certificate group and inheritable ACLs as described in the
operator guide.
