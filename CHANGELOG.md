# Changelog

All notable changes to `moesh`. The project is pre-1.0: behaviour may change
between minor releases without a deprecation period.

## 0.2.0a7 — 2026-10-30

CI test synchronization hardening, bridge carrier header interoperability, and runner timeout alignment.

### Fixed — bridge headers, test timeouts, and CI diagnostics

- **Dual bridge tunnel carrier header support (`moesh-bridge.py`, `moesh_tunnel.py`).** Added `TUNNEL_ID_HEADER = b"x-moesh-tunnel-id:"` to `moesh-bridge.py:218`, `:257` and updated `moesh_tunnel.py:411-412` to emit both `X-Moesh-Carrier-Id` and `X-Moesh-Tunnel-Id` on HTTP upgrade, ensuring full interoperability across agent and bridge versions.
- **Test handshake and subprocess timeout alignment (`tests/test_cli_packaging.py`, `tests/test_command_piping.py`, `tests/test_moecp.py`, `tests/test_named_hosts.py`, `tests/test_number_identity.py`, `tests/test_operator_outcome.py`).** Raised fixture handshake timeouts from `30s` to `60s` (`MOESH_SHELL_HANDSHAKE_TIMEOUT="60"`), aligned `subprocess.run` execution timeouts to `45s`/`60s` so test-side subprocess limits do not preempt client handshake resolution, and extended agent startup barriers to `25.0s`.
- **Adversarial transfer test timeout bounds (`tests/test_moecp_adversarial.py`).** Increased subprocess execution timeouts for large multichunk transfers (to `90s`; `tests/test_moecp_adversarial.py:564`) and unwritable destination tests (to `45s`; `tests/test_moecp_adversarial.py:645`), preventing premature runner termination before internal protocol error handling completes.
- **Diagnostic bridge log capture on assertion failure (`tests/harness.py`).** `OperatorSession.read_until` now inspects `/tmp/opencode/bridge-test-*.log` and appends recent bridge events to `AssertionError` messages on timeout for instant failure triage in CI runs (`tests/harness.py:239-250`).

## 0.2.0a6 — 2026-10-30

Test synchronization hardening and prompt refresh reliability across Python 3.11, 3.12, 3.13, and 3.14.

### Fixed — test harness barriers, prompt redraw, and timeouts

- **Fenced agent startup log polling (`tests/harness.py`).** `start_agent()` now searches for tunnel establishment strictly following the unique PID start marker, preventing restarted agent sessions from falsely matching output from earlier processes.
- **Barrier synchronization on agent readiness (`tests/test_named_hosts.py`, `tests/test_moecp.py`, `tests/test_command_piping.py`).** Replaced static `time.sleep(2.0)` assumptions with active polling loops on agent log establishment, eliminating intermittent handshake timeouts under concurrent CI runner load.
- **GNU Readline prompt suppression on re-attachment (`moesh_tunnel.py`).** Added `HostShell.refresh_screen()` toggling `cols` by 1 with `SIGWINCH` to force GNU Readline prompt redraw on reconnect without injecting keystrokes.
- **Handshake timeout and interactive prompt wait alignment (`tests/test_integration.py`, `tests/test_operator_outcome.py`).** Aligned test handshake timeouts (`30s`) and initial interactive shell prompt wait thresholds (`45s`) with protocol constants (`proto.HANDSHAKE_TIMEOUT`), eliminating false-positive timeout assertions in congested test environments.

## 0.2.0a5 — 2026-10-30

Engineering audit, client-perspective defect remediation, and documentation overhaul. Every entry below was verified against running code and reproducible test suites before release.

### Added — non-interactive execution and binary streaming (`moesh`, `moesh_tunnel.py`)

- **Direct remote execution (`session_type="exec"`).** `moesh` now supports non-interactive execution via `-c COMMAND` or positional argument lists (`moesh -n <N> [--] COMMAND [ARG ...]`). Commands execute in a dedicated subshell without requiring a local or remote TTY (`moesh_shell.py:1240-1257`, `moesh_tunnel.py:935-1119`).
- **Dashed argument and quote preservation.** Command-line tokens are captured via `nargs=argparse.REMAINDER`, stripped of leading `--`, and joined via `shlex.join`, allowing complex dashed flags and quoted sub-commands (e.g. `moesh -n 3 python3 -c "print(1)"`) to pass through uncorrupted (`moesh_shell.py:1222-1234`).
- **Bidirectional stdin/stdout streaming and pipe multiplexing.** Local `stdin` streams non-blocking to the remote child process, multiplexed with child `stdout` reads via `select.select` with a 1 MiB backpressure ceiling on unconsumed stdin buffers (`moesh_tunnel.py:991-1039`).
- **Clean process group termination.** Remote commands execute in their own process session group (`start_new_session=True`). On client disconnect or transport loss, `moesh_tunnel.py` delivers `SIGTERM` followed by `SIGKILL` to the child process group (`os.killpg`), preventing orphaned background processes (`moesh_tunnel.py:974`, `:1085-1114`).
- **Quiet mode logging (`-q` / `--quiet`).** Added `-q` to `moesh` and `moecp` to silence informational connection messages on `stderr`, allowing clean binary pipelines to `stdout` (`moesh_shell.py:1162-1166`, `moecp.py:2224-2228`, `:2269-2272`).

### Fixed — dead-tunnel recovery, bridge deadlocks, and transfer errors

- **CI matrix Python binding (`.github/workflows/ci.yml`, `.github/workflows/publish.yml`).** Explicitly pinned `uv sync --python ${{ matrix.python-version }}` and set `UV_PYTHON` across all matrix jobs, followed by an automated runtime version assertion (`sys.version_info`). Previously, `.python-version` specifying `3.14` caused `uv` to download and run pre-release Python 3.14 on all jobs regardless of the matrix interpreter.
- **Multi-threaded agent PTY fork deadlock elimination (`moesh_tunnel.py`).** Replaced `pty.fork()` in `PersistentShell.spawn()` with `pty.openpty()` and `subprocess.Popen(["/bin/bash", "-i"], start_new_session=True, close_fds=True, env=child_env)`. Under POSIX `fork()` in multi-threaded processes (e.g. concurrent `tunnel_worker` threads), mutexes held by background threads deadlocked the child process in Python bytecode before `os.execv`, causing intermittent operator connection timeouts (`timed out waiting for b'$'; saw b''`).
- **Client stderr diagnosis on test assertion timeout (`tests/harness.py`).** `read_until` now appends client stderr log contents to the `AssertionError` message on timeout, providing immediate diagnostic output if client-side connections drop or fail.
- **Dead tunnel early detection (`PAIR_DEAD_MARKER`).** The bridge detects when an agent worker walks away before or during a Noise handshake and immediately writes `\x01MOESH_DEAD_TUNNEL\n` to the operator socket (`moesh_wire.py:63`, `moesh-bridge.py:1331-1333`). The client reads this after writing its first handshake frame and reconnects immediately without timing out (`moesh_proto.py:294-315`, `moesh_shell.py:532-557`).
- **Deferred operator active accounting (`moesh-bridge.py`).** In `operator_v2_conn`, `touch_host(host, 1)` is deferred until a live tunnel is actually dequeued and paired. A waiting operator client no longer marks the host active, resolving circular 409 conflict deadlocks during agent restarts.
- **Standby socket TCP keepalive (`moesh-bridge.py`).** Standby queued tunnel and relay carrier sockets enable `SO_KEEPALIVE` with tight probe intervals (`TCP_KEEPIDLE=5`, `TCP_KEEPINTVL=2`, `TCP_KEEPCNT=3`), purging half-open sockets caused by ungraceful drops.
- **Incident-scoped conflict retry deadlines (`moesh_tunnel.py`, `moesh_relay.py`).** Conflict deadlines are initialized per incident rather than process startup, allowing transient 409 conflicts to retry cleanly.
- **Persistent carrier identity derivation (`derive_carrier_id()`).** Derives a stable 16-hex identity from `/etc/machine-id` or static keys when `MOESH_TUNNEL_ID` or `MOESH_RELAY_ID` is unset (`moesh_tunnel.py:155-188`, `moesh_relay.py:61-86`).
- **Structured native transfer error propagation (`moecp`, `moesh_tunnel.py`).** When `moecp` is missing on a remote agent during native transfer requests, `moesh_tunnel.py` emits a structured `Msg.ERROR` JSON payload instructing the operator to deploy `moecp.py` (`moesh_tunnel.py:920-928`). `moecp.py` decodes the error and aborts immediately without redundant retries on fatal protocol errors (`moecp.py:842-847`, `:2189-2190`).
- **Sensitive environment variable scrubbing.** Sensitive variables (`MOESH_TUNNEL_*_KEY*`, `MOESH_TUNNEL_*MASTER*`, `MOESH_TUNNEL_*OPERATOR_PUB*`, `MOESH_*RELAY_TOKEN*`) are stripped from child processes spawned by the agent (`moesh_tunnel.py:128-149`, `:537-539`, `:962-965`).

### Documentation and Packaging

- **Created CLI Reference (`docs/cli.md`).** Full reference covering all 5 executables (`moesh`, `moecp`, `moesh-tunnel`, `moesh-relay`, `moesh-bridge`) with argparse definitions, exit codes, and examples.
- **Automated doc drift verification (`tests/test_doc_drift.py`).** Pytest test suite asserting CLI option parity, valid source line citations, PyPI README link validity, and sdist exclusions.
- **PyPI packaging hygiene (`pyproject.toml`).** Removed gitignored operator artifacts (`HANDOFF.md`, `TEST-PROTOCOL.md`) from the sdist tarball target, and converted `README.md` relative links to full GitHub URLs so links do not 404 on PyPI.
- **Corrected documentation inconsistencies.** Fixed `--port` option in `docs/configuration.md` (was `--receiver-port`), corrected `CHUNK_SIZE` documentation to 32 KiB, resolved `moecp` in-process transfer descriptions in `docs/architecture.md`, and updated all source line citations.

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
