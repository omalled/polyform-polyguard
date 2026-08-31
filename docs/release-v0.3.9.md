# Polyguard v0.3.9

Polyguard v0.3.9 keeps an upstream HTTP/1.1 connection fully open until the application response
arrives. Requests are already unambiguously delimited by their HTTP framing and carry
`Connection: close`, so an immediate TCP write-side shutdown is unnecessary. Some application
servers interpret that early FIN as a client disconnect and close without a response.

The regression suite now models an upstream that waits briefly before responding and verifies
that Polyguard does not half-close the request during that interval. This covers the timing
difference that can appear between an interactive process and a managed service.

This change is confined to the proxy coordinator's upstream socket lifecycle. No typed Polyform
function contract or independent implementation changes in this release. The complete format,
warning-free strict-lint, dependency-audit, all-target test, differential-fuzzing, release-build,
older-userspace smoke, and artifact-checksum gates remain required.
