# Polyguard v0.3.6

Polyguard v0.3.6 corrects the hardened systemd deployment envelope for imported Nginx
configurations whose static `root` or `alias` directories are under `/home`. The service can now
see those paths through a read-only home-directory view; normal Unix traversal and read
permissions continue to apply, and the proxy receives no write access there.

The operator guide now documents dedicated certificate-reader group membership and inheritable
ACLs for root-readable certificate trees. This permits startup validation and safe renewal reloads
without running Polyguard as root or making private keys world-readable.

The proxy core and all independently registered implementations are unchanged from v0.3.5. The
complete format, warning-free strict-lint, dependency-audit, all-target test,
differential-fuzzing, release-build, older-userspace smoke, and artifact-checksum gates remain
required.
