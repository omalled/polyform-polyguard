# Polyguard v0.3.7

Polyguard v0.3.7 makes explicit IPv6 listener sockets IPv6-only before binding. This preserves the
listener semantics of imported Nginx configurations that declare separate IPv4 and IPv6 wildcard
listeners on the same port, and prevents the IPv6 socket from implicitly claiming the IPv4 port.

Coverage includes a socket-level regression and a compiled-executable integration test that loads
an Nginx configuration with `0.0.0.0` and `[::]` listeners sharing one port, then serves requests
over both IPv4 and IPv6.

This change is confined to the proxy coordinator's operating-system listener setup. No typed
Polyform function contract or independent implementation changes in this release. The complete
format, warning-free strict-lint, dependency-audit, all-target test, differential-fuzzing,
release-build, older-userspace smoke, and artifact-checksum gates remain required.
