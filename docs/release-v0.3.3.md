# Polyguard v0.3.3

Polyguard v0.3.3 corrects Nginx `add_header` inheritance inside supported request-method
conditions. Nginx replaces the inherited header set when a nested block declares `add_header`;
Polyguard now coalesces exactly equivalent sets without producing duplicate response headers.

Conditional header replacements that differ from the inherited set and cannot be expressed by
Polyguard's bounded route model are rejected rather than approximated. Conditional fixed-response
routes use the nested header set exactly, matching Nginx inheritance.

The portable statically linked x86-64 Linux artifact and the complete format, strict-lint,
dependency-audit, all-target test, differential-fuzzing, release-build, older-userspace smoke, and
artifact-checksum gates remain required.
