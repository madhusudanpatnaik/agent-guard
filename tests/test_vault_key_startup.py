"""Startup diagnostic for connector secrets encrypted under a different key.

The trap this catches, hit by following the documented setup order:
  1. `agentguard seed` with no AGENTGUARD_SECRET_KEY -> demo connector
     credentials are encrypted under the built-in dev default
  2. the operator sets AGENTGUARD_SECRET_KEY, as the README instructs for
     anything beyond local dev
  3. the server boots clean, the console loads, agents and policies all render
  4. the FIRST governed execute/query returns 400 "connector secret could not
     be decrypted (key rotated?)" — while the operator rotated nothing

Failing at request time, with a message that blames a rotation that never
happened, is the worst place to surface this. check_vault_key() moves it to
startup with a message that names the actual cause and the fix.
"""

from __future__ import annotations

from agentguard.main import check_vault_key
from agentguard.models import Connector
from agentguard.vault import encrypt_secret


def _add_connector(db, name: str, *, secret_ciphertext: str) -> None:
    db.add(Connector(name=name, base_url="http://127.0.0.1:9100", kind="http",
                     auth_type="bearer", auth_secret_encrypted=secret_ciphertext,
                     enabled=True, org_id=None))
    db.commit()


def test_no_warning_when_every_secret_decrypts(db):
    _add_connector(db, "good", secret_ciphertext=encrypt_secret("s3cret"))
    assert check_vault_key() is None


def test_no_warning_when_there_are_no_stored_secrets(db):
    """A fresh install with no connectors must boot silently."""
    assert check_vault_key() is None


def test_warns_when_a_secret_was_encrypted_under_a_different_key(db, monkeypatch):
    """Reproduces the documented-path trap: seeded first, key set afterwards."""
    from agentguard.config import get_settings

    # Encrypt under the key in force at "seed" time.
    _add_connector(db, "crm", secret_ciphertext=encrypt_secret("seeded-under-old-key"))

    # Operator now sets a different key, exactly as the README tells them to.
    monkeypatch.setattr(get_settings(), "vault_key", "a-different-key-" + "x" * 32)

    msg = check_vault_key()
    assert msg is not None, "startup gave no warning; failure would surface mid-request"
    assert "crm" in msg, "the warning must name which connector is affected"
    assert "rotate-vault-key" in msg, "the warning must state the remedy"


def test_check_never_raises_even_if_the_database_is_unusable(monkeypatch):
    """A diagnostic must not be able to prevent the server from starting."""
    from agentguard import main

    class _Boom:
        def __enter__(self):
            raise RuntimeError("db exploded")

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(main, "SessionLocal", lambda: _Boom())
    assert check_vault_key() is None
