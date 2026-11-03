#!/usr/bin/env python3
"""Acceptance and regression tests for relay TLS carrier support and token masking.

Measures:
1. TLS carrier upgrade connection over secure SSL sockets.
2. Rejection of invalid/self-signed certificates under default strict verification.
3. Strict enforcement: no silent fallback to plaintext HTTP on TLS handshake failure.
4. Insecure override (--tls-insecure / --insecure) for self-signed certificates.
5. Custom CA bundle verification (--tls-ca-cert).
6. Certificate SHA-256 fingerprint pinning (--tls-pin).
7. Probe status fetching over TLS.
8. Sensitive bearer token masking in logging and diagnostic output.
9. Session idle timeout disabled (<= 0) for long-running inference streaming.
"""

from __future__ import annotations

import contextlib
import datetime
import hashlib
import ipaddress
import json
import socket
import ssl
import threading
import time
from typing import TYPE_CHECKING

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import moesh_relay
from moesh_wire import RELAY_PAIR_MARKER
from tests.harness import Bridge, next_ports

if TYPE_CHECKING:
    from pathlib import Path


def _generate_test_cert(
    tmp_path: Path, common_name: str = "127.0.0.1"
) -> tuple[Path, Path, str]:
    """Generate a self-signed certificate and private key for testing.

    Returns (cert_path, key_path, sha256_fingerprint).
    """
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(x509.NameOID.COMMON_NAME, common_name)]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(hours=1)
        )
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc)
            + datetime.timedelta(days=1)
        )
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    cert_path = tmp_path / "test_cert.pem"
    key_path = tmp_path / "test_key.pem"

    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    cert_path.write_bytes(cert_bytes)

    key_bytes = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(key_bytes)

    der = cert.public_bytes(serialization.Encoding.DER)
    fingerprint = hashlib.sha256(der).hexdigest()
    return cert_path, key_path, fingerprint


class MockTLSServer:
    """Mock HTTP/HTTPS server for testing carrier handshake and probe endpoints."""

    def __init__(
        self,
        cert_path: Path | None = None,
        key_path: Path | None = None,
        is_tls: bool = True,
    ) -> None:
        self.is_tls = is_tls
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = int(self.sock.getsockname()[1])

        self.ssl_context: ssl.SSLContext | None = None
        if self.is_tls and cert_path and key_path:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.ssl_context.load_cert_chain(
                certfile=str(cert_path), keyfile=str(key_path)
            )

        self._running = True
        self.received_requests: list[bytes] = []
        self.thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> MockTLSServer:
        self.thread.start()
        return self

    def _run(self) -> None:
        while self._running:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                break
            threading.Thread(
                target=self._handle_conn, args=(conn,), daemon=True
            ).start()

    def _handle_conn(self, raw_conn: socket.socket) -> None:
        conn = raw_conn
        try:
            if self.ssl_context:
                conn = self.ssl_context.wrap_socket(
                    raw_conn, server_side=True
                )
            conn.settimeout(5.0)
            req = b""
            while b"\r\n\r\n" not in req:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req += chunk
            self.received_requests.append(req)

            if b"GET /__moesh/status" in req:
                body = json.dumps(
                    {
                        "hosts": {"in_use": ["host-1"], "free": ["host-2"]},
                        "relay": {"ports_open": [26426], "ports_free": [26427]},
                    }
                ).encode("utf-8")
                header = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Type: application/json\r\n"
                    b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
                    b"Connection: close\r\n\r\n"
                )
                conn.sendall(header + body)
            elif b"Upgrade: websocket" in req:
                resp = (
                    b"HTTP/1.1 101 Switching Protocols\r\n"
                    b"Upgrade: websocket\r\n"
                    b"Connection: Upgrade\r\n"
                    b"X-Moesh-Relay-Port: 26426\r\n"
                    b"X-Moesh-Relay-Pairing: event\r\n\r\n"
                    + RELAY_PAIR_MARKER
                )
                conn.sendall(resp)
                # Keep socket alive briefly for test assertion
                time.sleep(0.5)
            else:
                conn.sendall(b"HTTP/1.1 404 Not Found\r\n\r\n")
        except Exception:  # noqa: S110
            pass
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def stop(self) -> None:
        self._running = False
        with contextlib.suppress(OSError):
            self.sock.close()
        self.thread.join(timeout=1.0)


def test_mask_token() -> None:
    """moesh_relay.mask_token masks sensitive bearer tokens while preserving brevity."""
    assert moesh_relay.mask_token("") == ""
    assert moesh_relay.mask_token("secret") == "***"
    assert moesh_relay.mask_token("12345") == "***"
    assert moesh_relay.mask_token("sk-test-token-abcdef") == "sk-...def"
    assert moesh_relay.mask_token("bearer_super_secret_token") == "bea...ken"


def test_tls_rejects_self_signed_cert_without_silent_fallback(
    tmp_path: Path,
) -> None:
    """STRICT: Default TLS context rejects self-signed certificates and never falls back."""
    cert_path, key_path, _ = _generate_test_cert(tmp_path)
    server = MockTLSServer(cert_path, key_path, is_tls=True).start()
    try:
        # Default verification must fail loudly with SSLCertVerificationError
        with pytest.raises(
            (ssl.SSLCertVerificationError, ssl.SSLError, OSError)
        ) as exc_info:
            moesh_relay.connect_tunnel(
                "127.0.0.1",
                server.port,
                "/__relay/26426",
                tls=True,
                tls_insecure=False,
            )
        # Verify the failure was TLS certificate verification, not plaintext degradation
        assert (
            isinstance(exc_info.value, ssl.SSLError)
            or "certificate verify failed" in str(exc_info.value).lower()
        )
    finally:
        server.stop()


def test_tls_insecure_override_succeeds(tmp_path: Path) -> None:
    """--tls-insecure allows connecting to self-signed certificates in dev/test."""
    cert_path, key_path, _ = _generate_test_cert(tmp_path)
    server = MockTLSServer(cert_path, key_path, is_tls=True).start()
    try:
        sock, assigned, leftover, event_mode = moesh_relay.connect_tunnel(
            "127.0.0.1",
            server.port,
            "/__relay/26426",
            tls=True,
            tls_insecure=True,
        )
        try:
            assert isinstance(sock, ssl.SSLSocket)
            assert assigned == 26426
            assert event_mode is True
            assert leftover == RELAY_PAIR_MARKER
        finally:
            with contextlib.suppress(OSError):
                sock.close()
    finally:
        server.stop()


def test_tls_ca_cert_bundle_verification(tmp_path: Path) -> None:
    """--tls-ca-cert successfully verifies certificate signed by specified CA bundle."""
    cert_path, key_path, _ = _generate_test_cert(tmp_path)
    server = MockTLSServer(cert_path, key_path, is_tls=True).start()
    try:
        sock, assigned, _, _ = moesh_relay.connect_tunnel(
            "127.0.0.1",
            server.port,
            "/__relay/26426",
            tls=True,
            tls_ca_cert=str(cert_path),
        )
        try:
            assert isinstance(sock, ssl.SSLSocket)
            assert assigned == 26426
        finally:
            with contextlib.suppress(OSError):
                sock.close()
    finally:
        server.stop()


def test_tls_certificate_pinning(tmp_path: Path) -> None:
    """--tls-pin verifies exact SHA-256 fingerprint and rejects mismatches."""
    cert_path, key_path, fingerprint = _generate_test_cert(tmp_path)
    server = MockTLSServer(cert_path, key_path, is_tls=True).start()
    try:
        # Colon-formatted matching pin must succeed
        colon_pin = ":".join(
            fingerprint[i : i + 2] for i in range(0, len(fingerprint), 2)
        )
        sock, _assigned, _, _ = moesh_relay.connect_tunnel(
            "127.0.0.1",
            server.port,
            "/__relay/26426",
            tls=True,
            tls_insecure=True,
            tls_pin=colon_pin,
        )
        with contextlib.suppress(OSError):
            sock.close()

        # Mismatching pin must fail immediately with SSLCertVerificationError
        wrong_pin = "aa" * 32
        with pytest.raises(ssl.SSLCertVerificationError) as exc:
            moesh_relay.connect_tunnel(
                "127.0.0.1",
                server.port,
                "/__relay/26426",
                tls=True,
                tls_insecure=True,
                tls_pin=wrong_pin,
            )
        assert "fingerprint mismatch" in str(exc.value)
    finally:
        server.stop()


def test_fetch_status_over_tls(tmp_path: Path) -> None:
    """fetch_status queries /__moesh/status over TLS with cert options."""
    cert_path, key_path, _ = _generate_test_cert(tmp_path)
    server = MockTLSServer(cert_path, key_path, is_tls=True).start()
    try:
        status = moesh_relay.fetch_status(
            "127.0.0.1",
            server.port,
            auth_token="test-secret-token",  # noqa: S106
            tls=True,
            tls_insecure=True,
        )
        assert status["hosts"]["in_use"] == ["host-1"]
        assert status["relay"]["ports_open"] == [26426]
    finally:
        server.stop()


def test_probe_logs_mask_sensitive_token(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """print_probe diagnostic failure output masks auth tokens in stdout/stderr."""
    # Dial an unreachable port to provoke diagnostic log
    rc = moesh_relay.print_probe(
        "127.0.0.1",
        1,
        auth_token="sk-secret-bearer-token-12345",  # noqa: S106
        tls=False,
    )
    assert rc == 1
    captured = capsys.readouterr()
    # Masked token format must appear, but NOT raw bearer token
    assert "sk-secret-bearer-token-12345" not in captured.out
    assert "sk-secret-bearer-token-12345" not in captured.err
    assert "sk-...345" in captured.out or "sk-...345" in captured.err


def test_splice_disabled_session_idle_timeout() -> None:
    """splice with idle_timeout <= 0 sets socket timeout to None for long-running inference."""
    s1_a, s1_b = socket.socketpair()
    s2_a, s2_b = socket.socketpair()

    done = threading.Event()

    def run_splice() -> None:
        try:
            # Setting idle_timeout=0 disables timeout
            moesh_relay.splice(s1_a, s2_a, idle_timeout=0)
        finally:
            done.set()

    t = threading.Thread(target=run_splice, daemon=True)
    t.start()

    # Sockets must have timeout None
    assert s1_a.gettimeout() is None
    assert s2_a.gettimeout() is None

    # Bi-directional transmission works
    s1_b.sendall(b"prompt: 1000 tokens")
    assert s2_b.recv(1024) == b"prompt: 1000 tokens"

    s2_b.sendall(b"response: generation")
    assert s1_b.recv(1024) == b"response: generation"

    # Close sockets cleanly
    s1_b.close()
    s2_b.close()
    t.join(timeout=2.0)
    assert not t.is_alive()


def test_bridge_direct_tls_termination_and_probe(tmp_path: Path) -> None:
    """moesh-bridge terminates TLS natively when provisioned with cert and key."""
    cert_path, key_path, fingerprint = _generate_test_cert(tmp_path)
    tunnel_port, operator_port, operator_v2_port = next_ports()

    bridge = Bridge(
        tunnel_port=tunnel_port,
        operator_port=operator_port,
        operator_v2_port=operator_v2_port,
        env_extra={
            "MOESH_BRIDGE_TLS_CERT": str(cert_path),
            "MOESH_BRIDGE_TLS_KEY": str(key_path),
        },
    )
    try:
        bridge._wait_for_line(
            f"tunnel listening on 127.0.0.1:{tunnel_port} (TLS)"
        )

        # 1. Probe status over TLS with self-signed certificate insecure override
        status = moesh_relay.fetch_status(
            "127.0.0.1",
            tunnel_port,
            tls=True,
            tls_insecure=True,
        )
        assert "relay" in status
        assert "hosts" in status

        # 2. Strict verification with custom CA cert bundle
        status_ca = moesh_relay.fetch_status(
            "127.0.0.1",
            tunnel_port,
            tls=True,
            tls_ca_cert=str(cert_path),
        )
        assert status_ca == status

        # 3. Strict verification with TLS pin
        status_pin = moesh_relay.fetch_status(
            "127.0.0.1",
            tunnel_port,
            tls=True,
            tls_insecure=True,
            tls_pin=fingerprint,
        )
        assert status_pin == status

        # 4. Plaintext HTTP client to TLS bridge is rejected / closed
        with pytest.raises((ConnectionError, socket.error)):
            moesh_relay.fetch_status(
                "127.0.0.1",
                tunnel_port,
                tls=False,
            )
    finally:
        bridge.stop()

