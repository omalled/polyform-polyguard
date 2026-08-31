# Polyguard v0.3.2

Polyguard v0.3.2 fixes relative Nginx `include` resolution. Relative includes are now resolved
from the root configuration prefix, matching Nginx behavior when files under directories such as
`sites-enabled` include shared files from the configuration root.

The loader remains fail-closed: missing includes, wildcard-directory patterns, cycles, excessive
depth, excessive file counts, and excessive aggregate size are rejected. A regression test covers
the standard nested-site/shared-parameter layout.

The portable statically linked x86-64 Linux artifact and the complete format, strict-lint,
dependency-audit, all-target test, differential-fuzzing, release-build, older-userspace smoke, and
artifact-checksum gates remain required.
