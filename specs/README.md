# Specifications

Describe the complete behavior of the software before asking agents to write
implementations. For every public function in the design, include:

- its purpose;
- the exact input and output types;
- the errors callers may receive;
- precise behavior and security rules;
- concrete examples with expected results.

The examples are part of the specification. `polyform generate --count 5`
first asks Codex to turn the specification into shared conformance tests, then
asks separate agents to create five implementations of every function. Humans
review the specification and generated code; they are not expected to hand-write
all of those implementations.

The test-author agent also creates a local differential fuzz harness. Run
`polyform fuzz` after generation to send identical generated inputs through
every implementation and save minimized disagreements as regression cases.
