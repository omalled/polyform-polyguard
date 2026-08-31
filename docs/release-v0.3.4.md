# Polyguard v0.3.4

Polyguard v0.3.4 supports Nginx configurations where a shared parameter include and its enclosing
location repeat the same `proxy_set_header` name and value. Byte-for-byte identical entries are
coalesced into one canonical upstream field.

Same-name entries with different values remain unsupported and fail closed. This keeps Polyguard's
single-valued security metadata invariant while allowing redundant standard include layouts to
migrate without producing ambiguous upstream request headers.

The portable statically linked x86-64 Linux artifact and the complete format, strict-lint,
dependency-audit, all-target test, differential-fuzzing, release-build, older-userspace smoke, and
artifact-checksum gates remain required.
