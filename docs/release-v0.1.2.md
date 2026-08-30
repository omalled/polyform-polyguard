# Polyguard v0.1.2 release notes

Polyguard v0.1.2 completes hosted telemetry compatibility after live integration testing.

The hosted API accepts per-call metadata only for implementation IDs active in the signed
composition. Polyguard still executes the server-selected primary plus independently admitted
local peers for agreement, but now submits only the invoked server-active calls to the hosted
execution endpoint. Additional invoked peers remain represented by the local startup selection
map and fail-closed disagreement outcome; no unassigned identity is misrepresented as active.

The patch adds regression coverage for both the hosted outcome vocabulary and composition-member
filtering. The proxy's protocol behavior, 65-entry registry, agreement width, limits, and public
interfaces are unchanged.
