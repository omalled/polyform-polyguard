# Polyguard v0.1.1 release notes

Polyguard v0.1.1 is a telemetry-compatibility patch for the initial v0.1.0 release. The proxy,
five-way implementation registry, agreement behavior, protocol limits, and public interfaces are
unchanged.

The patch maps per-call outcomes to the hosted Polyform API's bounded vocabulary: `ok`,
`error`, `timeout`, and `panic`. Ordinary execution success remains an explicit boolean,
and disagreements remain identified by the fixed `implementation_disagreement` execution error
kind plus the affected function and implementation IDs. No request data is added to telemetry.

The release is built from the public source tree, must pass the complete Polyform evidence gate,
and is published with a signed release identity and immutable SHA-256 checksums.
