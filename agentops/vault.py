"""Credential vault — encrypts connector secrets at rest.

Operators register upstream connectors (a CRM, a payments API, a database) whose
credentials the control plane holds *on the agent's behalf*. Agents never see
these secrets: they ask the plane to execute an action, and the plane injects the
credential when it calls the upstream. Secrets are encrypted at rest with
AES-128-CBC + HMAC (Fernet), keyed from the deployment ``secret_key`` — so a
database dump alone never yields usable upstream credentials.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings


def _fernet_for(secret: str) -> Fernet:
    # Derive a stable 32-byte Fernet key from a secret.
    digest = hashlib.sha256(secret.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def _fernet() -> Fernet:
    return _fernet_for(get_settings().effective_vault_key())


def encrypt_secret(plaintext: str) -> str:
    if plaintext is None:
        plaintext = ""
    return _fernet().encrypt(plaintext.encode()).decode()


def decrypt_secret(token: str) -> str:
    if not token:
        return ""
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:  # wrong key / tampered ciphertext
        raise ValueError("connector secret could not be decrypted (key rotated?)") from exc


def reencrypt_secret(token: str, old_secret: str, new_secret: str) -> str:
    """Decrypt a token under ``old_secret`` and re-encrypt it under ``new_secret``."""
    if not token:
        return ""
    plaintext = _fernet_for(old_secret).decrypt(token.encode()).decode()
    return _fernet_for(new_secret).encrypt(plaintext.encode()).decode()
