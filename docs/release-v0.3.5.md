# Polyguard v0.3.5

Polyguard v0.3.5 completes bounded `Expect: 100-continue` handling. A valid expectation is accepted
only after request framing, authority, route, and declared body-size validation. Proxy routes then
receive one interim response before Polyguard reads the body, and the consumed `Expect` field is
not forwarded upstream. Unsupported or repeated expectations return `417 Expectation Failed`.

Declared content lengths now encounter the selected route's body limit before any route action or
interim response. Static routing also matches Nginx precedence for unsupported methods: a missing
resource remains `404 Not Found`, while an existing resource returns `405 Method Not Allowed`.

These changes are in the bounded proxy coordinator. They do not alter a Polyform function's typed
contract or merge any independently registered implementations. The complete format,
warning-free strict-lint, dependency-audit, all-target test, differential-fuzzing, release-build,
older-userspace smoke, and artifact-checksum gates remain required.
