import pytest
from cryptography.fernet import Fernet

from interlock.connections.fabric.credentials import FabricCredentialError, FabricKeyring


def keyring(monkeypatch, active="v1", refs=None):
    monkeypatch.setenv("FABRIC_KEY_1", Fernet.generate_key().decode())
    return FabricKeyring(active, refs or {"v1": "env://FABRIC_KEY_1"})


def test_ciphertext_hides_tokens_and_binds_record_owner(monkeypatch):
    keys = keyring(monkeypatch)
    ciphertext = keys.encrypt("access-token refresh-token", source_id="one", purpose="cache")
    assert b"access-token" not in ciphertext and b"refresh-token" not in ciphertext
    assert (
        keys.decrypt(ciphertext, source_id="one", purpose="cache") == "access-token refresh-token"
    )
    with pytest.raises(FabricCredentialError):
        keys.decrypt(ciphertext, source_id="two", purpose="cache")
    with pytest.raises(FabricCredentialError):
        keys.decrypt(ciphertext, source_id="one", purpose="pending")


def test_rotation_reads_old_key_and_writes_new_key(monkeypatch):
    old = keyring(monkeypatch)
    blob = old.encrypt("cache", source_id="one", purpose="cache")
    monkeypatch.setenv("FABRIC_KEY_2", Fernet.generate_key().decode())
    new = FabricKeyring("v2", {"v1": "env://FABRIC_KEY_1", "v2": "env://FABRIC_KEY_2"})
    assert new.decrypt(blob, source_id="one", purpose="cache") == "cache"
    assert new.encrypt("cache", source_id="one", purpose="cache").startswith(b"v2:")
    with pytest.raises(FabricCredentialError):
        FabricKeyring("v2", {"v2": "env://FABRIC_KEY_2"}).decrypt(
            blob, source_id="one", purpose="cache"
        )
    monkeypatch.setenv("FABRIC_KEY_1", Fernet.generate_key().decode())
    with pytest.raises(FabricCredentialError):
        FabricKeyring("v1", {"v1": "env://FABRIC_KEY_1"}).decrypt(
            blob, source_id="one", purpose="cache"
        )


@pytest.mark.parametrize("refs", [{}, {"v1": "literal-key"}, {"v1": "env://DOES_NOT_EXIST"}])
def test_missing_or_literal_key_fails_closed(refs):
    with pytest.raises(FabricCredentialError):
        FabricKeyring("v1", refs)
