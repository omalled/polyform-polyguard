# Polyguard v0.3.8

Polyguard v0.3.8 enables `SO_REUSEADDR` before binding traffic and management listeners. This
allows a listener to take over a recently closed production address while prior connections
finish their kernel lifecycle, matching the established behavior expected of long-running proxy
servers.

The listener regression suite now verifies both `SO_REUSEADDR` and IPv6-only behavior before
proving that explicit IPv4 and IPv6 wildcard listeners can share a port. The compiled-executable
integration test continues to serve requests over both address families.

This change is confined to the proxy coordinator's operating-system listener setup. No typed
Polyform function contract or independent implementation changes in this release. The complete
format, warning-free strict-lint, dependency-audit, all-target test, differential-fuzzing,
release-build, older-userspace smoke, and artifact-checksum gates remain required.
