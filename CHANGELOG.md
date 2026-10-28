# Changelog

All notable changes to `moesh`. The project is pre-1.0: behaviour may change
between minor releases without a deprecation period.

## 0.2.0a4 — 2026-10-28

Engineering audit and remediation. Every entry below was reproduced with an
executable test before it was changed; the audit findings that were *falsified*
are recorded too, because "we looked and the defect was not there" is a result.

### Fixed — transfer integrity (`moecp`)

- **PULL no longer trusts a stale ledger record.** Deduplication now compares
  the remote content identity reported by the current manifest, so replacing a
  remote file with different bytes of the same size and mtime cannot be
  silently skipped.
- **Symlinked path components cannot escape the destination root.** Native
  PUSH, local PULL and staging resolve through the real filesystem and refuse
  a destination whose resolution leaves the designated root.
- **Decompression is bounded.** Frames are validated after decompression as
  well as before, and the cumulative decoded byte count is capped by the
  declared file size.
- **Recursive PULL manifests are streamed in bounded pages** instead of one
  JSON document for the whole tree, so trees of 100,000 files transfer with
  bounded memory and stay inside the 64 KiB frame limit.
- **Resume validates durable content** rather than trusting recorded progress:
  an interrupted transfer resolves to safe resume, clean retry, or an explicit
  failure, never a false completion.

### Fixed — bridge and relay ownership (`moesh-bridge.py`, `moesh_relay.py`)

- **Lease admission is atomic and fenced by generation.** Exactly one carrier
  is admitted per host slot or relay port; conflicting carriers receive
  `409 Conflict`, and a socket left in the queue by an earlier owner is
  discarded instead of being spliced into the new owner's traffic.
- **Relay carriers are authorized.** `MOESH_BRIDGE_RELAY_TOKEN` (when set)
  gates relay registration and the status probe; without it the bridge logs
  that relay registration is open, and the documentation says so.
- **Server-first backends work through the relay.** A carrier's connection to
  its local target no longer waits for the peer to speak first, so an
  SMTP-style greeting reaches the client. Standby tunnels are refreshed rather
  than exhausted.
- **TCP half-close is honoured in both directions.** A client may shut down
  its write direction and still receive the complete response; the surviving
  direction is drained for `MOESH_BRIDGE_HALFCLOSE_LINGER` seconds and then
  closed, so no forwarding thread is left blocked.
- **Relay-registry growth is bounded** (`MOESH_BRIDGE_MAX_RELAY_QUEUES`), with
  predictable refusal instead of unbounded queues, leases and descriptors.

### Fixed — assurance and packaging

- **CI and the release gate run the complete test suite**, not a single file,
  and a clean-wheel install must start all five entry points before anything
  publishes.
- **Two stale expected-failure oracles were replaced by behaviour tests.**
  `INT-001`/`INT-002` asserted that a symbol name appeared inside a slice of
  source text; one raised `IndexError` on an anchor that no longer exists, so
  its "expected failure" measured nothing. Both invariants hold in the current
  bridge and are now measured through the real status probe.
- **Packaging metadata matches reality**: the build comments describe the two
  supported surfaces (source checkout and installed wheel), the development
  classifier is Alpha (the version is `0.2.0a4`), and the declared changelog
  location is this file.

### Documentation

- `SECURITY.md` uses the current script names for key generation.
- The relay's confidentiality boundary is stated where it is claimed: the
  shell tunnel is encrypted end to end, the relay carries raw TCP and the
  bridge is blind to both.
- Session persistence is scoped to what is implemented: a shell survives the
  operator disconnecting, not the agent process exiting.
- Performance claims are reproducible: `bench/moesh_bench.py` measures each
  stage separately and `docs/performance.md` records the numbers with hardware
  context.
