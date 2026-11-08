# Outbound TCP Reverse Relay (`moesh-relay`)

`moesh-relay` is a zero-dependency outbound TCP reverse port relay. It allows an agent machine located behind NAT, firewalls, or ephemeral environments (e.g. Kaggle, Vast.ai, RunPod) to expose a local TCP port back through the public receiver machine without opening inbound firewall ports or running SSH daemons.

**Source:** `moesh_relay.py:1-872`

---

## Architecture & How It Works

1. **Carrier Dialout**: The relay daemon dials outbound to the receiver's HTTP/HTTPS port with an `HTTP/1.1` Upgrade request on `/__relay/<port>` (or `/__relay/auto` / `/__relay/<service>`).
2. **Lease Admission & Standby Queue**: The receiver bridge (`moesh-bridge.py`) verifies that no conflicting carrier holds the requested port or name. It grants admission and queues the socket in a standby pool.
3. **Connection Pairing**: When an external client connects to the published TCP port on the receiver (e.g. `:26426`), the bridge pairs the connection with the oldest standby tunnel.
4. **Immediate Replenishment**: The worker hands the active session off to a dedicated worker thread and dials a replacement standby tunnel immediately, preventing HTTP keep-alive connection pools from depleting standby capacity.
5. **Bidirectional Splice**: Data is pumped bidirectionally between the receiver socket and the local target, preserving TCP half-close semantics.

---

## Carrier TLS Configuration

`moesh-relay` supports secure TLS transport for carrier dialouts to the receiver bridge.

### Auto-Detection & Flags

- **Auto-Detection**: Specifying an `https://` URL (e.g. `--url https://receiver.example.com/__relay/auto`) automatically enables TLS and defaults the port to `443`.
- **Explicit TLS Flag**: `--tls` enables TLS explicitly.
- **Port Selection**: When TLS is active and no port is specified, `443` is used as the default port (falling back to `80` for plaintext).
- **Strict Error Handling**: If TLS is requested but cannot be established, the relay aborts loudly; it will **never** silently fall back to plaintext HTTP.

### Certificate Verification & Pinning

- **Default Verification**: Standard CA certificates are verified using `ssl.create_default_context()`.
- **Self-Signed Certificates (Dev/Test)**: Use `--tls-insecure` or `--insecure` to bypass verification when developing against local or testing proxies.
- **Custom CA Bundles**: Use `--tls-ca-cert <path>` to provide an enterprise or private CA certificate file.
- **Certificate Pinning**: Use `--tls-pin <sha256_hex>` to pin the expected SHA-256 fingerprint of the receiver's certificate. The fingerprint is verified immediately after the TLS handshake and rejects mismatches before transmitting authentication tokens or headers.

---

## Security Boundary & Authentication

Understanding the security boundary is critical when designing production deployments:

1. **Carrier Authentication (`X-Moesh-Relay-Auth` / `--token`)**:
   - Authenticates the **agent carrier** to the receiver bridge when `MOESH_BRIDGE_RELAY_TOKEN` is configured.
   - Prevents unauthorized agents from registering relays, occupying ports, or eavesdropping on lease state via `/__moesh/status`.
   - All secret tokens are masked in logs (e.g. `abc...xyz`).
2. **Data-Plane Boundary**:
   - The bridge acts as a **blind socket pump**; it does not inspect, terminate TLS for, or authenticate TCP payload streams passing through the paired relay.
   - Anyone on the public internet who connects to the receiver's exposed relay port (e.g. `26426`) reaches the upstream target service.
3. **Application-Level Security**:
   - Upstream services must never assume incoming TCP connections from `moesh-relay` are authenticated.
   - Application-level authentication (API keys, mTLS, HTTP basic auth) must be enforced directly on the backend service or via a local reverse proxy.

---

## High-Throughput / Long-Running Inference Deployments

By default, paired TCP sessions have a 120-second idle timeout (`--session-idle 120`) to bound half-closed or orphaned sockets.

For LLM inference workloads (e.g. vLLM, Ollama, TGI, llama.cpp), long prefill phases or streaming generation may result in periods without incoming socket activity. Setting `--session-idle 0` (or negative) completely disables the active session timeout.

### Example: Secure vLLM Exposure

```sh
# 1. Launch vLLM on localhost only (plaintext). The backend is reached through
#    the relay; vLLM is not exposed on the public network.
python3 -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3-8B-Instruct \
    --host 127.0.0.1 \
    --port 8000 \
    --api-key "<MODEL_API_KEY>"

# 2. Expose vLLM through the relay. --tls encrypts the carrier hop
#    (agent -> bridge) only; the public relay port stays plaintext raw TCP.
#    --session-idle 0 keeps long prefill/generation sessions open.
moesh-relay \
    --receiver receiver.example.com \
    -R 26426 \
    --name vllm-llama3 \
    --tls \
    --token "<RELAY_AUTH_TOKEN>" \
    --target 127.0.0.1:8000 \
    --session-idle 0

# 3. Client queries through the receiver's published port.
#    Port 26426 is plaintext raw TCP (the bridge terminates TLS only on the
#    tunnel listener, not on relay ports), so the client URL is http://:
curl http://receiver.example.com:26426/v1/chat/completions \
    -H "Authorization: Bearer <MODEL_API_KEY>" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "meta-llama/Llama-3-8B-Instruct",
        "messages": [{"role": "user", "content": "How do kernel pipes work?"}]
    }'
```

**TLS boundaries (honest):**

- **Carrier TLS (`--tls`, moesh_relay.py:134-148)**: encrypts the agent→bridge carrier hop only and is terminated at the bridge. `create_ssl_context` is called only by the outbound dial paths (`fetch_status`, `connect_tunnel`, `main`).
- **Bridge listener TLS (`--tls-cert/--tls-key`, moesh-bridge.py:1997-2019)**: direct TLS termination on the **tunnel listener** only. The public relay ports (26420-26430, moesh-bridge.py:2028-2082) get no `ssl_context` — they are plaintext.
- **Backend TLS**: terminates behind the relay on the agent host (e.g. vLLM behind a local TLS-terminating front). This tree does not vendor vLLM's own TLS flags, so do not invent a `vLLM --ssl` flag; use any TLS-terminating front. Note that `moesh-relay` dials its `--target` as plain TCP, so backend TLS does not ride the relay pipe itself.

Because the relay port is plaintext, `curl https://receiver.example.com:26426/...` is **unsupported as written**. For true client↔backend TLS end-to-end, terminate TLS at a front in front of the relay port (e.g. nginx TLS on :443 → plaintext to :26426) and/or have the backend speak TLS; the bridge is blind and never terminates TLS for the relayed stream (moesh-bridge.py:31-32).

### Example: Exposing llama.cpp / Ollama with SHA-256 Pinning

For self-hosted quantized models via `llama.cpp` (`llama-server`) or `ollama`:

```sh
# 1. Run llama-server locally on 127.0.0.1:8080 with API key
./llama-server \
    -m models/llama-3.1-8b-instruct.Q4_K_M.gguf \
    --host 127.0.0.1 \
    --port 8080 \
    --api-key "<MODEL_API_KEY>"

# 2. Expose llama-server with strict TLS certificate pinning and unbounded session idle
moesh-relay \
    --receiver receiver.example.com \
    -R 26428 \
    --name llama-cpp \
    --tls \
    --tls-pin "<SHA256_CERTIFICATE_FINGERPRINT>" \
    --token "<RELAY_AUTH_TOKEN>" \
    --target 127.0.0.1:8080 \
    --session-idle 0
```
