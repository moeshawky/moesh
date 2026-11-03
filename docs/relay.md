# Outbound TCP Reverse Relay (`moesh-relay`)

`moesh-relay` is a zero-dependency outbound TCP reverse port relay. It allows an agent machine located behind NAT, firewalls, or ephemeral environments (e.g. Kaggle, Vast.ai, RunPod) to expose a local TCP port back through the public receiver machine without opening inbound firewall ports or running SSH daemons.

**Source:** `moesh_relay.py:1-836`

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
# 1. Launch vLLM with an API key bound to localhost
python3 -m vllm.entrypoints.openai.api_server \
    --model meta-llama/Llama-3-8B-Instruct \
    --host 127.0.0.1 \
    --port 8000 \
    --api-key "<MODEL_API_KEY>"

# 2. Expose vLLM over TLS with carrier authentication and unbounded generation time
moesh-relay \
    --receiver receiver.example.com \
    --tls \
    --token "<RELAY_AUTH_TOKEN>" \
    --service vllm-llama3 \
    --target 127.0.0.1:8000 \
    --session-idle 0

# 3. Client queries model through the receiver's published port
curl https://receiver.example.com:26426/v1/chat/completions \
    -H "Authorization: Bearer <MODEL_API_KEY>" \
    -H "Content-Type: application/json" \
    -d '{
        "model": "meta-llama/Llama-3-8B-Instruct",
        "messages": [{"role": "user", "content": "How do kernel pipes work?"}]
    }'
```

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
    --tls \
    --tls-pin "<SHA256_CERTIFICATE_FINGERPRINT>" \
    --token "<RELAY_AUTH_TOKEN>" \
    --service llama-cpp \
    --target 127.0.0.1:8080 \
    --session-idle 0
```
