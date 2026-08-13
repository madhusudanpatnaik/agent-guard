"""Certificate authority for the TLS-intercepting proxy.

To govern HTTPS traffic the proxy must terminate TLS: it presents the agent a
certificate for the destination host, signed by the **AgentGuard CA**. The operator
installs that CA once in the agent's trust store (or container image); after that
every HTTPS request the agent makes is decrypted, governed, and re-encrypted to
the real origin — which the proxy verifies normally.

The CA private key is generated once and stored on disk (dir configurable via
``AGENTGUARD_PROXY_CA_DIR``). Leaf certs are minted on demand per host and cached.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
import tempfile
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


class ProxyCA:
    def __init__(self, ca_dir: str):
        self.dir = Path(ca_dir)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.cert_path = self.dir / "agentguard-ca.crt"
        self.key_path = self.dir / "agentguard-ca.key"
        self._leaf_dir = Path(tempfile.mkdtemp(prefix="agentguard-leaf-"))
        self._lock = threading.Lock()
        self._ctx_cache: dict[str, ssl.SSLContext] = {}
        self._ca_cert, self._ca_key = self._load_or_create()

    # -- CA lifecycle -----------------------------------------------------
    def _load_or_create(self):
        if self.cert_path.exists() and self.key_path.exists():
            cert = x509.load_pem_x509_certificate(self.cert_path.read_bytes())
            key = serialization.load_pem_private_key(self.key_path.read_bytes(), password=None)
            return cert, key
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AgentGuard"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AgentGuard Proxy CA"),
        ])
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, key_cert_sign=True, crl_sign=True,
                    key_encipherment=False, content_commitment=False,
                    data_encipherment=False, key_agreement=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self.key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        os.chmod(self.key_path, 0o600)
        return cert, key

    @property
    def ca_cert_pem(self) -> str:
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # -- per-host leaf certs ---------------------------------------------
    def _mint_leaf(self, host: str) -> tuple[Path, Path]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        try:
            san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
        except ValueError:
            san = x509.DNSName(host)
        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)]))
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName([san]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(self._ca_key, hashes.SHA256())
        )
        safe = host.replace(":", "_").replace("/", "_")
        cert_file = self._leaf_dir / f"{safe}.crt"
        key_file = self._leaf_dir / f"{safe}.key"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ))
        return cert_file, key_file

    def context_for_host(self, host: str) -> ssl.SSLContext:
        with self._lock:
            ctx = self._ctx_cache.get(host)
            if ctx is not None:
                return ctx
            cert_file, key_file = self._mint_leaf(host)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            self._ctx_cache[host] = ctx
            return ctx
