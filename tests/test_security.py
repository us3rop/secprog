import json
import os
from concurrent.futures import ThreadPoolExecutor

import pytest
from Crypto.Random import get_random_bytes

from sfm import crypto, storage
from sfm.crypto import VaultError
from sfm.vault import initialize, unlock, validate_name

PASSWORD = "test master password phrase"


@pytest.fixture(scope="module")
def encrypted():
    return crypto.encrypt(PASSWORD, bytearray(get_random_bytes(32)), {})


@pytest.mark.parametrize("field", ["wrapped_key", "payload"])
@pytest.mark.parametrize("part", ["nonce", "data", "tag"])
def test_ciphertext_tampering_rejected(encrypted, field, part):
    envelope = json.loads(encrypted)
    raw = bytearray(crypto.decode(envelope[field][part]))
    raw[0] ^= 1
    envelope[field][part] = crypto.encode(raw)
    with pytest.raises(VaultError, match="wrong password or corrupted vault"):
        crypto.decrypt(PASSWORD, crypto.pack(envelope))


def test_kdf_cost_rejected_before_derivation(encrypted, monkeypatch):
    envelope = json.loads(encrypted)
    envelope["header"]["N"] = 2**40
    def forbidden(*args):
        pytest.fail("untrusted KDF settings reached scrypt")
    monkeypatch.setattr(crypto, "derive", forbidden)
    with pytest.raises(VaultError):
        crypto.decrypt(PASSWORD, crypto.pack(envelope))


@pytest.mark.parametrize("raw", [b"", b"not json", b"[]", b"null", b'{"header":{}}'])
def test_malformed_vault_rejected(raw):
    with pytest.raises(VaultError):
        crypto.decrypt(PASSWORD, raw)


@pytest.mark.parametrize("name", ["", ".", "..", "../escape", "/absolute", "a/b", "a\\b", "bad\nname", "\x1b[31m", "x" * 256])
def test_names(name):
    with pytest.raises(VaultError):
        validate_name(name)


def test_atomic_failure_preserves_previous_data(tmp_path, monkeypatch):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        storage.atomic_write(fd, "target", b"old")
        def fail(*args, **kwargs):
            raise OSError("simulated disk failure")
        monkeypatch.setattr(storage.os, "replace", fail)
        with pytest.raises(OSError):
            storage.atomic_write(fd, "target", b"new")
        assert (tmp_path / "target").read_bytes() == b"old"
        assert sorted(p.name for p in tmp_path.iterdir()) == ["target"]
    finally:
        os.close(fd)


def test_size_limit_and_special_files(tmp_path):
    source = tmp_path / "big"
    source.write_bytes(b"12345")
    with pytest.raises(VaultError):
        storage.read_regular(source, 4)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(VaultError):
        storage.read_regular(fifo, 4)
    hardlink = tmp_path / "hardlink"
    os.link(source, hardlink)
    with pytest.raises(VaultError):
        storage.read_regular(hardlink, 10)


def test_concurrent_updates_are_serialized(tmp_path):
    path = tmp_path / "vault"
    initialize(path, PASSWORD)
    sources = [tmp_path / "one", tmp_path / "two"]
    for source in sources:
        source.write_text(source.name)
    def add(source):
        with unlock(path, PASSWORD) as vault:
            vault.add(source)
    with ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(add, sources))
    with unlock(path, PASSWORD) as vault:
        assert set(vault.entries) == {"one", "two"}


def test_symlink_vault_and_loose_permissions(tmp_path):
    path = tmp_path / "vault"
    initialize(path, PASSWORD)
    link = tmp_path / "link"
    link.symlink_to(path, target_is_directory=True)
    with pytest.raises(OSError):
        with unlock(link, PASSWORD):
            pass
    path.chmod(0o755)
    with pytest.raises(VaultError):
        with unlock(path, PASSWORD):
            pass


def test_empty_and_binary_contents_survive_rotation(tmp_path):
    path = tmp_path / "vault"
    initialize(path, PASSWORD)
    for name, content in (("empty", b""), ("binary", bytes(range(256)))):
        source = tmp_path / name
        source.write_bytes(content)
        with unlock(path, PASSWORD) as vault:
            vault.add(source)
    new_password = "replacement master passphrase"
    with unlock(path, PASSWORD) as vault:
        vault.master[:] = get_random_bytes(32)
        vault.password = new_password
        vault.save()
    with unlock(path, new_password) as vault:
        assert crypto.decode(vault.entries["empty"]["data"]) == b""
        assert crypto.decode(vault.entries["binary"]["data"]) == bytes(range(256))


def test_insecure_terminal_fallback_is_rejected(tmp_path, monkeypatch):
    import getpass
    import warnings
    from sfm.cli import main
    def fallback(*args):
        warnings.warn("cannot hide password", getpass.GetPassWarning)
        pytest.fail("must not accept echoing input")
    monkeypatch.setattr("sfm.cli.getpass.getpass", fallback)
    assert main(["--vault", str(tmp_path / "vault"), "init"]) == 1
    assert not (tmp_path / "vault").exists()
