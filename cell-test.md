# Cell 1 - moesh: the encrypted tunnel to the receiver.
#
# Transport : HTTP/1.1 on TCP/80 to the receiver's nginx. The request asks for
#             a 101 with the token `moesh-tunnel-v2`; the connection is NOT a
#             WebSocket and carries no RFC 6455 framing.
# Crypto    : Noise_XX_25519_ChaChaPoly_BLAKE2s between the operator and this
#             agent. The receiver's bridge relays the ciphertext and never
#             holds plaintext terminal data. No SSH, no TLS, no FRP, no QUIC.
# Payload   : /bin/bash on a PTY, carried as encrypted length-prefixed records.
#             The operator advertises its real terminal size; nothing is fixed
#             at 40x120 any more.
# Direction : this cell dials OUT to the receiver, so Kaggle needs no inbound
#             port and nothing here listens on a public interface.
#
# The shell SURVIVES disconnects: when the operator detaches, the interactive
# Bash keeps running, and the next operator re-attaches to the same shell with
# its working directory, variables and background jobs intact. The agent is the
# durable process; the shell outlives individual sessions.
#
# STOP AND RERUN, WITHOUT RESTARTING THE KERNEL:
#   * Re-running this cell stops the previous agent by PID (never by a command
#     line pattern), waits for it to exit and for its shell to be reaped, then
#     starts a new one. A stale agent cannot shadow the new tunnel.
#   * Stopping this cell (or interrupting it) leaves the agent running in its
#     own session, so the tunnel stays up.
#   * Stopping cell 3 stops the keepalive only; the tunnel is unaffected.
#
# The agent is downloaded from the upstream repository and started in its own
# session, so this cell returns in a few seconds and cell 3 can run. It
# redials after every operator session, so a dropped connection does not need
# a cell re-run.
#
# ONE KEY, ONE MASTER (the operator's rule, 2026-10-25):
#   This notebook's static private key is DERIVED from the fleet master with
#   HKDF-SHA256; it is never carried as a key of its own. The master is the
#   only secret, and the number below selects the identity.
#
#   Provisioning, once per notebook:
#     * The master is the `master =` line in the receiver's
#       ~/.config/moesh/hosts.toml (a new fleet: `moesh --new-master -n N`).
#     * Add that hex value to Kaggle's secret store under the name
#       MOESH_TUNNEL_MASTER, then re-run this cell.
#
#   The operator reaches this notebook with `moesh -n 3`. Both ends derive the
#   same key from the same master and the same number, so there is no
#   per-host public key to pin anywhere.
#
# The postcondition is the agent's own log line "upgraded", not a live
# process: a running daemon that never got a 101 is not a tunnel.

import os
import signal
import subprocess
import sys
import time
import urllib.request

NOTEBOOK = 3
"""THE ONE NUMBER. It selects this notebook's NAME, exactly like the port
number in the operator's old SSH host entries: change it and the receiver
routes to a different notebook. The operator reaches the same notebook with
`moesh -n 3`.

The name selects the route, and the master selects the key: the same master
and the same name derive the same static key on both sides (HKDF-SHA256).

Set NOTEBOOK = None to keep the plain name "default" (the mode the first
notebook used)."""

label = NOTEBOOK if NOTEBOOK is not None else "default"
"""The name this notebook answers to, as one value: the number when there is
one, the plain name otherwise."""

def config_value(name: str, default: str) -> str:
    """Read a config value from Kaggle secrets, then environment, then default.

    Unlike secret_value this makes no master-shape demand: host names, ports
    and paths are not 64-hex values, so they must not be validated as masters.

    Args:
        name: The secret / environment variable name.
        default: The fallback when the value is nowhere set.

    Returns:
        The configured value, or default.
    """
    try:
        from kaggle_secrets import UserSecretsClient
    except Exception:  # pragma: no cover - not a Kaggle kernel
        return os.environ.get(name, default)
    try:
        value = UserSecretsClient().get_secret(name)
    except Exception:  # pragma: no cover - missing or unreadable secret
        value = None
    if value and value.strip():
        return value.strip()
    return os.environ.get(name, default)


RECEIVER_HOST = config_value("MOESH_TUNNEL_RECEIVER", "129.80.112.57")
"""The receiver that owns the bridge. The bridge answers the 101 and pairs
this tunnel with the operator's terminal."""

RECEIVER_PORT = int(config_value("MOESH_TUNNEL_RECEIVER_PORT", "80"))
"""Plain HTTP on the receiver. There is no TLS: the payload is Noise
encrypted end to end, and the transport only carries ciphertext."""

TUNNEL_PATH = config_value("MOESH_TUNNEL_PATH", "/__moesh/tunnel")
"""The receiver's nginx maps /__moesh/ to the bridge, which keys its queues
by the path and the host name appended to it (measured: the bridge's v2 path
is /__moesh/tunnel)."""

BASE = "/kaggle/working" if os.path.isdir("/kaggle/working") else os.getcwd()

AGENT_FILES = ("moesh_wire.py", "moesh_proto.py", "moesh_tunnel.py", "moecp.py", "moesh_shell.py")
"""The agent and the modules it imports, fetched from the upstream
repository. Measured 2026-10-25: these are the published names and each one
answers HTTP 200; the earlier `_v2` names answer 404 on every surface."""

GITHUB_RAW = "https://raw.githubusercontent.com/moeshawky/moesh/master/"
GITHUB_URLS = (GITHUB_RAW,)
NOISE_REQUIREMENT = "noiseprotocol==0.3.1"

MASTER_SECRET_NAME = "MOESH_TUNNEL_MASTER"
"""The ONE secret this notebook needs: the fleet master from which the static
key is derived. The alias below is accepted so an already-provisioned secret
keeps working, but this is the canonical name."""

MASTER_SECRET_ALIASES = ("MOESH_TUNNEL_V2_MASTER",)
OPERATOR_PUB_SECRET_NAME = "MOESH_TUNNEL_OPERATOR_PUB"
OPERATOR_PUB_PIN = "260c67d30007b4be22975eaab0275c54e86d8d748b73141f581cdc0184a1582d"
"""The operator's static public key, pinned here so a notebook with no secret
store still authenticates. It is a PUBLIC key - measured as the contents of
the receiver's ~/.config/moesh/operator.key.pub - and a rotated operator key
wins over the pin through the secret store."""

LEGACY_KEY_VARS = (
    "MOESH_TUNNEL_AGENT_KEY",
    "MOESH_TUNNEL_V2_AGENT_KEY",
    "NB_TUNNEL_V2_AGENT_KEY",
    "MOESH_TUNNEL_AGENT_KEYFILE",
    "MOESH_TUNNEL_V2_AGENT_KEYFILE",
    "NB_TUNNEL_V2_AGENT_KEYFILE",
)
"""The retired raw-key routes. They are removed from the agent's environment
so that "one key, one master" is enforced by the environment the agent
actually sees, not only by the agent's order of preference."""

AGENT_PATH = os.path.join(BASE, "moesh_tunnel.py")
PID_FILE = os.path.join(BASE, "moesh_tunnel.pid")
SHELL_PID_FILE = os.path.join(BASE, "moesh_tunnel.shell.pid")
LOG_PATH = os.path.join(BASE, "moesh_tunnel.log")


def ensure_noise() -> None:
    """Install the Noise implementation if it is missing.

    The protocol has no hand-rolled fallback: the handshake imports `noise`
    lazily, so a missing package would surface as a failed handshake rather
    than as a missing dependency. Installing it here makes the failure loud
    and early, before the tunnel is claimed to be up.

    Raises:
        SystemExit: the package could not be installed.
    """
    try:
        import noise  # noqa: F401
        return
    except ImportError:
        pass
    result = None
    for extra in ([], ["--break-system-packages"]):
        result = subprocess.run(
            [sys.executable, "-m", "pip", "install", "--quiet", *extra, NOISE_REQUIREMENT],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            break
    try:
        import noise  # noqa: F401
    except ImportError as error:
        message = "could not install %s:\n%s\n%s" % (
            NOISE_REQUIREMENT,
            result.stdout[-800:],
            result.stderr[-800:],
        )
        raise SystemExit(message) from error


def fetch(url: str) -> bytes:
    """Download one URL.

    Args:
        url: The absolute URL to read.

    Returns:
        The response body.

    Raises:
        urllib.error.URLError: the URL could not be read.
    """
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()


def download(name: str) -> bytes:
    """Download one agent file from the first surface that answers.

    Args:
        name: The file's name inside the upstream repository.

    Returns:
        The file's bytes.

    Raises:
        RuntimeError: no surface answered.
    """
    failure = None
    for base in GITHUB_URLS:
        try:
            return fetch(base + name)
        except Exception as error:  # noqa: BLE001 - try the next surface
            failure = error
    raise RuntimeError("cannot download %s from the upstream: %r" % (name, failure))


def _platform_secret(name: str) -> str:
    """Read a secret from Kaggle's secret store.

    Kaggle does not necessarily inject secrets into the process environment;
    the supported route is the `kaggle_secrets` client, the same route this
    notebook's other cells use. The value is never printed.

    Args:
        name: The secret's name.

    Returns:
        The secret's value, or "" when it is absent or unreadable.
    """
    try:
        from kaggle_secrets import UserSecretsClient
    except Exception:  # pragma: no cover - not a Kaggle kernel
        return ""
    try:
        value = UserSecretsClient().get_secret(name)
    except Exception:  # pragma: no cover - missing or unreadable secret
        return ""
    return value.strip() if isinstance(value, str) else ""


def _clean(raw: str) -> str:
    """Normalise a hex secret: strip whitespace and the hex separators.

    Args:
        raw: The value as it was written down.

    Returns:
        The value as bare hex.
    """
    return raw.strip().removeprefix("0x").replace(":", "").replace(" ", "")


def _looks_like_master(value: str) -> bool:
    """Return True when the value is 64 hex characters.

    A master secret is 32 bytes, hex encoded. A value that merely looks
    secret-ish - a path, a flag, a placeholder - must never be mistaken for
    one, because a wrong master produces a tunnel that authenticates nobody.

    Args:
        value: The candidate value.

    Returns:
        True when the value has the shape of a master secret.
    """
    cleaned = _clean(value)
    if len(cleaned) != 64:
        return False
    try:
        int(cleaned, 16)
    except ValueError:
        return False
    return True


def _master_files() -> list:
    """Return the candidate master files inside a mounted private dataset.

    A private Kaggle dataset is a normal way to hand a secret to a notebook:
    the operator uploads a file with the master and the notebook reads it from
    the mounted dataset. The search is bounded and explicit.

    Returns:
        The paths that exist, in a stable order.
    """
    found = []
    roots = [
        root.strip()
        for root in os.environ.get(
            "MOESH_TUNNEL_MASTER_ROOTS", "/kaggle/input,/kaggle/secrets"
        ).split(",")
        if root.strip()
    ]
    names = ("master.key", "moesh_master.key")
    for root in roots:
        if not os.path.isdir(root):
            continue
        for entry in sorted(os.listdir(root)):
            directory = os.path.join(root, entry)
            if not os.path.isdir(directory):
                continue
            for name in names:
                candidate = os.path.join(directory, name)
                if os.path.isfile(candidate):
                    found.append(candidate)
    return found


def secret_value(name: str, required: bool = False) -> str:
    """Return a secret from wherever this environment keeps it.

    Routes, in order: the platform secret store, the environment, the file
    named by `<NAME>_FILE`, and a master file inside a mounted dataset.

    Args:
        name: The secret's name.
        required: Fail loudly when the secret is absent.

    Returns:
        The secret's value, normalised, or "" when it is absent.

    Raises:
        SystemExit: the secret was required and was not found.
    """
    value = _platform_secret(name)
    if not _looks_like_master(value):
        value = os.environ.get(name, "").strip()
    if not _looks_like_master(value):
        path = os.environ.get("%s_FILE" % name, "").strip()
        if path:
            try:
                with open(path, "r", encoding="ascii") as handle:
                    value = handle.read().strip()
            except OSError:
                value = ""
    if not _looks_like_master(value):
        for candidate in _master_files():
            try:
                with open(candidate, "r", encoding="ascii") as handle:
                    content = handle.read().strip()
            except OSError:
                continue
            if _looks_like_master(content):
                value = content
                break
    value = _clean(value)
    if not value and required:
        raise SystemExit("secret %s not provisioned" % name)
    return value


def pid_alive(pid: int) -> bool:
    """Return True when the process is still running.

    Args:
        pid: The process id to probe.

    Returns:
        True when the process exists.
    """
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def running_agents(script_path: str) -> list:
    """Return the PIDs of the agents started from `script_path`.

    The match is on the exact script path in the argument vector, not on a
    substring of a command line: a pattern match would also hit this cell.

    Args:
        script_path: The absolute path the agent is started from.

    Returns:
        The matching PIDs, in ascending order.
    """
    found = []
    try:
        entries = os.listdir("/proc")
    except OSError:
        return found
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open("/proc/%s/cmdline" % entry, "rb") as handle:
                argv = handle.read().split(b"\0")
        except OSError:
            continue
        if any(part.decode("utf-8", "replace") == script_path for part in argv):
            found.append(int(entry))
    return found


def stop_previous_agents(script_path: str) -> list:
    """Stop a previous agent and wait for it to exit.

    The agent terminates its shell when it stops, so no Bash is left running
    and no stale tunnel can shadow the new one.

    Args:
        script_path: The absolute path the agent is started from.

    Returns:
        The PIDs it stopped, in ascending order.
    """
    pids = set(running_agents(script_path))
    try:
        with open(PID_FILE, "r", encoding="ascii") as handle:
            pids.add(int(handle.read().strip()))
    except (OSError, ValueError):
        pass
    pids.discard(os.getpid())
    if not pids:
        return []
    for pid in sorted(pids):
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError:
            pass
    deadline = time.time() + 15
    while time.time() < deadline:
        if not [pid for pid in pids if pid_alive(pid)]:
            break
        time.sleep(0.3)
    for pid in sorted(pids):
        if pid_alive(pid):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
    return sorted(pids)


def log_text() -> str:
    """Return the agent's log so far.

    Returns:
        The log's text, or "" when it cannot be read yet.
    """
    try:
        with open(LOG_PATH, "r", encoding="utf-8", errors="replace") as reader:
            return reader.read()
    except OSError:
        return ""


def agent_public_key(text: str) -> str:
    """Return the static public key the agent logged, or "".

    The agent prints it as it starts each session. It is a PUBLIC key, and it
    is the one value that lets the operator confirm that both ends derived
    the SAME identity: "the tunnel is up" and "the tunnel is up and the two
    ends agree" are different claims.

    Args:
        text: The agent's log.

    Returns:
        The hex public key, or "" when the line is not there yet.
    """
    for line in text.splitlines():
        if "agent static public key:" in line:
            return line.split("agent static public key:", 1)[1].strip()
    return ""


ensure_noise()

for artifact in AGENT_FILES:
    with open(os.path.join(BASE, artifact), "wb") as handle:
        handle.write(download(artifact))

master = ""
master_name = MASTER_SECRET_NAME
for candidate in (MASTER_SECRET_NAME,) + MASTER_SECRET_ALIASES:
    master = secret_value(candidate)
    if master:
        master_name = candidate
        break

if not master:
    raise SystemExit(
        "the fleet master secret is not provisioned.\n"
        "On the receiver:  the `master =` line of ~/.config/moesh/hosts.toml\n"
        "  (a new fleet:  moesh --new-master -n %s)\n"
        "In Kaggle: add that hex value as the secret %s, then re-run this cell.\n"
        "The master is the only secret this notebook needs: the static key is "
        "derived from it and from this notebook's number." % (label, MASTER_SECRET_NAME)
    )

operator_pub = secret_value(OPERATOR_PUB_SECRET_NAME) or OPERATOR_PUB_PIN

stopped = stop_previous_agents(AGENT_PATH)
if stopped:
    print("stopped previous agent(s): %s" % ", ".join(str(pid) for pid in stopped))

environment = dict(os.environ)
for legacy in LEGACY_KEY_VARS:
    environment.pop(legacy, None)
environment["MOESH_TUNNEL_MASTER"] = master
environment["MOESH_TUNNEL_RECEIVER"] = RECEIVER_HOST
environment["MOESH_TUNNEL_RECEIVER_PORT"] = str(RECEIVER_PORT)
environment["MOESH_TUNNEL_PATH"] = TUNNEL_PATH
environment["MOESH_TUNNEL_HOST"] = str(label)
environment["MOESH_TUNNEL_OPERATOR_PUB"] = operator_pub
environment["MOESH_TUNNEL_CHILD_PIDFILE"] = SHELL_PID_FILE

log_handle = open(LOG_PATH, "w")
daemon = subprocess.Popen(
    [sys.executable, AGENT_PATH],
    stdout=log_handle,
    stderr=subprocess.STDOUT,
    start_new_session=True,
    env=environment,
)
log_handle.close()
with open(PID_FILE, "w", encoding="ascii") as handle:
    handle.write(str(daemon.pid))

upgraded = False
try:
    for _ in range(90):
        time.sleep(0.5)
        if daemon.poll() is not None:
            break
        if "upgraded" in log_text():
            upgraded = True
            break
except KeyboardInterrupt:
    print("interrupted; the agent keeps running (pid %d)" % daemon.pid)
    raise

if not upgraded:
    tail = log_text()[-2000:]
    message = (
        "the tunnel agent did not reach the receiver.\n"
        "receiver: %s:%d%s\n"
        "agent log:\n%s\n"
        "Re-run this cell; the previous agent is stopped automatically."
    ) % (RECEIVER_HOST, RECEIVER_PORT, TUNNEL_PATH, tail)
    raise SystemExit(message)

print("tunnel agent pid %d" % daemon.pid)
print("receiver: %s:%d%s" % (RECEIVER_HOST, RECEIVER_PORT, TUNNEL_PATH))
print("log:", LOG_PATH)
print("master read from the secret %s (never printed)" % master_name)
published = agent_public_key(log_text())
if published:
    print("agent static public key: %s" % published)
print()
print("CONNECT FROM THE RECEIVER (this host), in a real terminal:")
print()
print("    /home/ubuntu/.local/bin/moesh -n %s" % (label))
print()
print("The number above is this notebook's name: the receiver keeps one queue")
print("per name, and the key on both sides is derived from the same master,")
print("so there is no per-host key to pin anywhere.")
print()
print("For a clean shell:  /home/ubuntu/.local/bin/moesh -n %s --fresh" % label)
print("Leave this notebook running; cell 3 keeps the session alive.")
print()
print("=" * 72)
print("DIAGNOSTICS (share these with the operator for the race investigation):")
print("=" * 72)
print("agent pid   :", daemon.pid)
print("agent log   :", LOG_PATH)
print("receiver    :", "%s:%d%s" % (RECEIVER_HOST, RECEIVER_PORT, TUNNEL_PATH))
print()
print("To fetch the agent log from the receiver, run on the receiver:")
print("    cat %s" % LOG_PATH)
print()
print("Key lines to look for (with timestamps):")
print("  'upgraded'                              - tunnel established")
print("  'tunnel established; waiting for an operator' - ready for pairing")
print("  'transport ended without an authenticated close (abrupt EOF)' - client drop observed")
print("  'run_session: transport EOF while draining' - EOF during session")
print("  next 'upgraded' after an EOF line       - re-dial happened")
print()
print("Bridge log on the receiver: /var/log/moesh-bridge.log")
print("Key lines: 'pairing operator-v2[...] with a host', 'pair closed',")
print("  'host tunnel v2 attached', 'discarding stale ... tunnel'")
print("=" * 72)
