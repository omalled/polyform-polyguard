# Polyguard architecture

Polyguard is a single-process, security-first HTTP/1.1 reverse proxy. Its distinguishing
control is interpretation diversity: bounded request metadata is interpreted by multiple
independent implementations from the generated Polyform registry, and a security-relevant
disagreement causes rejection and connection closure before upstream request bytes are written.

## Request path

1. The listener accepts a bounded number of TCP connections and applies read deadlines.
2. A bounded reader obtains one request line and header section without consuming body bytes.
3. Selected independent registry implementations parse the same immutable byte slices.
4. Typed results—including every `bytes_consumed` boundary—must agree exactly.
5. Independent policy functions determine framing, normalize the target, reconcile authority,
   select a route, construct forwarding metadata, and remove hop-by-hop fields.
6. Polyguard serializes one canonical upstream HTTP/1.1 request head. A selected serializer's
   output must agree with its peers and reparse to the agreed typed meaning.
7. The body is copied according to the single agreed framing: exactly the declared length, or
   decoded chunk boundaries with bounded trailers. The proxy never uses request close-delimiting.
8. The upstream response is relayed with explicit bounds and deadlines. This first release does
   not reuse client or upstream connections; `Connection: close` makes message boundaries clear.
9. Access metrics use fixed outcome categories. Request targets, headers, bodies, authorities,
   client addresses, credentials, and error text are excluded from Polyform telemetry.

## Trust boundaries

- Client bytes are hostile until independently parsed and compared.
- Configuration is operator-controlled but validated at startup.
- Listener-derived peer address and scheme are trusted inputs to forwarding policy.
- Incoming forwarding headers are trusted only when the listener policy explicitly enables it.
- Upstream responses are untrusted and subject to response limits and timeouts.
- Polyform runtime composition data selects admitted implementation identities; it does not
  bypass local availability, quarantine, or minimum-agreement checks.

## Diversity and composition

Each registry entry contains one independently generated implementation of one deterministic
function. Agreement mode selects at least two available implementations per critical function,
executes them over identical typed inputs, and compares `Result<T, PolyguardError>` values.
Selection is observable through startup diagnostics and a privacy-safe readiness view.

The official vendored Polyform runtime authenticates release delegation and signed composition
assignments. The assigned implementation is placed first for its function and local admitted
peers fill the remaining agreement slots. Calls actually executed are recorded as fixed
function/implementation/outcome/duration telemetry; no request values are included.

If a selected identity is absent or quarantined, startup fails unless a valid composition with
the configured minimum agreement width can be formed. Polyguard never silently falls back from
agreement mode to a single parser.

## Resource model

Protocol limits are defined in `specs/polyform.toml` and enforced before proportional
allocation. Runtime configuration adds connection concurrency, request-body, response-header,
response-body, and timeout bounds. Each connection has a bounded lifetime, and graceful
shutdown stops accepting new connections before waiting for active work.

## Deliberate non-goals

Polyform is not used to reimplement TLS, cryptography, asynchronous scheduling, sockets, DNS,
or operating-system primitives. Those belong to mature libraries and the Rust standard
ecosystem. The generated functions are deterministic interpretation and policy cores only.
