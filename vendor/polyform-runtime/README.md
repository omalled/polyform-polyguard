# polyform-runtime

Application-facing Rust library for registering an installation, loading its
runtime composition, refreshing after interventions, and sending
privacy-minimal execution metadata. Applications keep their dispatch logic and
behavioral contracts; this crate handles the shared control-plane protocol.

The runtime verifies a release-key delegation before trusting the server's
separate online composition key. Every register and refresh response binds the
release ID, client ID, request nonce, monotonic list version, composition
revision, complete implementation-status list, and assigned IDs into an
Ed25519 signature. Assignments are checked against the binary's own inventory
and persisted before becoming active. Forged, replayed, older, incomplete, and
unknown assignments leave the current composition unchanged. A locally
remembered quarantine can be lifted only by an explicit active status in a
higher signed list version.
