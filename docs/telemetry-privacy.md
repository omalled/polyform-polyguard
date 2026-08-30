# Telemetry privacy

Polyguard separates local structured diagnostics from Polyform operational telemetry.

Polyform telemetry contains only project/release identifiers, installation/composition and
implementation identities supplied by the runtime, a fixed outcome category, a success bit,
bounded duration/counter values supported by the official client, and clearly labeled synthetic
test markers where supported. It must not contain request targets, headers, bodies, credentials,
cookies, tokens, client IP addresses, authorities, route names, upstream response content, raw
errors, hashes of user content, or truncated user content.

The classifier accepts only these fixed codes: `accepted`, `client_syntax`,
`ambiguous_framing`, `policy_rejected`, `route_missing`, `upstream_failure`, `timeout`,
`implementation_disagreement`, and `internal_failure`. Unknown or contradictory inputs are
rejected with `SerializationInvariant` so content-derived strings cannot accidentally enter an
event.

Synthetic dashboard exercises are labeled and use generated installation identifiers stored
outside the repository. Tokens, signing private keys, browser state, and private installation
identifiers are never committed. The final lifecycle report records aggregate counts and safe
public URLs only.
