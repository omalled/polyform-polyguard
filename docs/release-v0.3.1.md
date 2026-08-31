# Polyguard v0.3.1

Polyguard v0.3.1 adds a statically linked x86-64 Linux release artifact for broad distribution
compatibility. The portable artifact is built with the MUSL target, checked to be statically
linked, and executed inside an Ubuntu 18.04 userspace before publication.

The native Linux GNU artifact remains available for systems with a compatible glibc. Operators
should choose `polyguard-x86_64-unknown-linux-musl` when portability across Linux distribution
versions matters.

All proxy behavior and the Nginx compatibility envelope are unchanged from v0.3.0. The complete
format, strict-lint, dependency-audit, all-target test, differential-fuzzing, release-build, and
artifact-checksum gates remain required.
