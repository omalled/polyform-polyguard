# Operator guide

## Startup

Start from `polyguard.example.toml`, keep the listener on loopback while validating a deployment,
and define every route's upstream by name. Configuration is rejected before listening when an
address, route, limit, timeout, security mode, implementation identity, or agreement width is
invalid. The startup record identifies the selected implementation composition without printing
request or credential data.

Agreement mode is the production default. Set `agreement_implementations` to at least two. A
larger width trades CPU time for more independent interpretations. Never compensate for an
unavailable or quarantined implementation by lowering the width on a running production service.

## Endpoints

- `/_polyguard/health` reports whether the process can serve local requests.
- `/_polyguard/ready` reports whether configuration and the implementation composition remain deployable.
- `/_polyguard/metrics` exposes bounded counters using fixed outcome names; it has no target, authority,
  client-address, header, or body labels.

These endpoints should be limited to a management network at the deployment boundary. They are
served locally by Polyguard and are never forwarded upstream.

## Shutdown and deadlines

`SIGINT` and `SIGTERM` initiate graceful shutdown: the listener stops accepting, active requests
receive up to `graceful_shutdown_timeout_ms`, and the process then exits. Client request heads,
request bodies, upstream connects, and upstream responses have separate deadlines. A timeout is
closed and counted; Polyguard does not attempt to recover an ambiguous stream.

## Logging and telemetry

Operational records are newline-delimited JSON with timestamps, event names, fixed outcome
categories, implementation identities, and numeric duration/size fields. Do not add request
targets, header values, bodies, authorities, credentials, raw client addresses, or free-form
parser errors. Polyform product telemetry follows the narrower contract in
`telemetry-privacy.md`.

## Polyform runtime composition

After installing a published release, configure its release trust evidence and a writable private
state file:

```toml
[polyform]
base_url = "https://omalled.com/polyform"
trust_file = "/etc/polyguard/release-trust.json"
state_file = "/var/lib/polyguard/composition.json"
strategy = "balanced"
refresh_interval_seconds = 300
report_telemetry = true
required = true
```

The official vendored runtime authenticates release delegation and signed assignments, rejects
rollback or unknown IDs, and persists state before activation. The assigned ID is the primary
member of Polyguard's local agreement set; it never reduces `agreement_implementations`. A failed
refresh retains the last verified composition. `required = false` permits an explicitly logged
startup fallback to the local static agreement set when registration is unavailable.

## Upgrades and TLS

The v0.1.0 listener is cleartext HTTP/1.1. Terminate TLS at a maintained edge proxy and restrict
the network hop to Polyguard. WebSocket upgrade requests are parsed and classified but rejected;
there is no partial tunnel mode. HTTP/2 prefaces, unsupported transfer codings, close-delimited
request bodies, pipelining behind a body boundary, and ambiguous framing are rejected.

## Incident response

If disagreement telemetry appears, preserve only the synthetic or already-sanitized reproducer,
record the active composition and artifact checksum, and follow
`remediation-workflow-proposal.md`. Quarantine affects admission immediately; deployment remains
blocked until the configured width can be satisfied by non-quarantined implementations and the
full verification gates pass.
