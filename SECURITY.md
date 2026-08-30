# Security policy

Polyguard treats parsing differentials, request-boundary confusion, authority ambiguity,
hop-by-hop leakage, forwarding-header spoofing, and accidental sensitive telemetry as security
issues.

## Supported versions

Only the most recent tagged release receives security fixes. Until v0.1.0 is published, the
default branch is development software and must not be exposed directly to untrusted networks.

## Reporting a vulnerability

Please use GitHub's private vulnerability-reporting flow for this repository. Do not include
live credentials, access tokens, private request data, or production traffic captures. A useful
report contains a minimal synthetic byte sequence, expected and observed behavior, the Polyguard
version, operating system, configuration with secrets removed, and whether any upstream bytes
were written.

We will acknowledge a report as soon as practical, reproduce it against the conformance and
differential harnesses, and coordinate disclosure after a fixed release is available. Public
issues are appropriate for non-sensitive correctness and hardening suggestions.

## Operational guidance

Run Polyguard with a dedicated unprivileged account, bind only intended interfaces, restrict
upstream network access, retain bounded structured logs, and keep agreement mode at two or more
implementations. A composition containing a quarantined implementation must not be deployed.
