# Polyguard v0.3.10

Polyguard v0.3.10 publishes its canonical Polyform release against the portable x86-64 Linux
artifact used by production deployments. This makes the runtime trust metadata's artifact digest
match the binary that registers for signed compositions and reports execution telemetry.

There is no proxy behavior change in this release. No typed Polyform function contract or
independent implementation changed. The complete format, warning-free strict-lint,
dependency-audit, all-target test, differential-fuzzing, release-build, older-userspace smoke,
and artifact-checksum gates remain required.
