# Implementation diversity review

Polyguard v0.1.0 contains exactly five accepted implementations for each of 13 public
specification functions (65 registry entries). Every entry owns its interpretation logic and
implements exactly one public function. Shared code is limited to data models, dispatch,
networking, and tests; there is no shared HTTP parser hidden beneath the variants.

| Function | Independent structures represented |
| --- | --- |
| Request line | state pipeline; direct guards; typed rule wrappers; decision machine; reverse-offset scan |
| Header section | typed cursor; state phases; decision table; algebraic lines; transition reducer |
| Body framing | metadata transitions; direct wrappers; rule matrix; stream machine; bounded domain |
| Chunk metadata | rule pipeline; guarded parts; invariant spans; symbol iterator; composable segments |
| Trailers | invariant trie; transition phases; direct table; validated invariants; event automaton |
| Request target | rule table; validated pipeline; invariant offsets; typed matrix; composable validators |
| Authority | validation phases; invariant table; composable components; segment pipeline; endpoint algebra |
| Hop-by-hop fields | rule set; composable guards; typed events; sorted plan; byte trie |
| Canonical request | rule phases; composable table; compiled plan; dual sink; reverse fill |
| Route matching | direct domain scan; validation pipeline; bounded match; typed arithmetic; immutable table |
| Forwarding policy | decision table; direct match; transition model; central transition table; primitive boundary |
| Upgrade policy | composable table; invariant signature; observation table; transformation matrix; obligation algebra |
| Telemetry outcome | bounded rules; symbol phases; length dispatch; fingerprint index; word composition |

The review checked control flow, intermediate representation, lookup/storage choice, validation
order, allocation strategy, and output construction—not identifier names. Conformance,
round-trip, differential fuzz, and real-proxy tests use the single shipping registry. A permanent
test asserts 65 unique IDs, one function pointer per entry, and exactly five entries per function.
