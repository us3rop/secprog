"""Authenticated vault session and logical file-name validation."""
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from Crypto.Random import get_random_bytes

from sfm import crypto, storage
from sfm.crypto import AUTH_ERROR, VaultError, decode, encode


def validate_name(name):
    if (not isinstance(name, str) or not 1 <= len(name) <= 255
            or name in {".", ".."} or "/" in name or "\\" in name
            or not name.isprintable()):
        raise VaultError("name must be 1–255 printable characters without path separators")
    return name


def validate_entries(entries):
    try:
        if not isinstance(entries, dict) or len(entries) > 10000:
            raise ValueError
        for name, entry in entries.items():
            validate_name(name)
            if set(entry) != {"data", "size", "created", "modified"}:
                raise ValueError
            data = decode(entry["data"])
            if type(entry["size"]) is not int or entry["size"] != len(data):
                raise ValueError
            if len(data) > storage.MAX_FILE:
                raise ValueError
            for field in ("created", "modified"):
                if not isinstance(entry[field], str) or len(entry[field]) > 40:
                    raise ValueError
                datetime.fromisoformat(entry[field])
    except (ValueError, TypeError, KeyError, VaultError, OverflowError):
        raise VaultError(AUTH_ERROR) from None


def timestamp():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Vault:
    def __init__(self, fd, password, master, entries):
        self.fd, self.password, self.master, self.entries = fd, password, master, entries

    def save(self):
        storage.atomic_write(self.fd, "vault.json",
                             crypto.encrypt(self.password, self.master, self.entries))

    def add(self, source, name=None):
        name = validate_name(name if name is not None else Path(source).name)
        if name in self.entries:
            raise VaultError("name already exists")
        data = storage.read_regular(Path(source).expanduser(), storage.MAX_FILE)
        now = timestamp()
        self.entries[name] = {"data": encode(data), "size": len(data),
                              "created": now, "modified": now}
        self.save()

    def require(self, name):
        validate_name(name)
        if name not in self.entries:
            raise VaultError("file not found in vault")
        return self.entries[name]


def initialize(path, password):
    with storage.locked_vault(path, create=True) as fd:
        master = bytearray(get_random_bytes(32))
        try:
            Vault(fd, password, master, {}).save()
        finally:
            master[:] = b"\0" * len(master)


@contextmanager
def unlock(path, password):
    with storage.locked_vault(path) as fd:
        master, entries = crypto.decrypt(password, storage.load(fd))
        try:
            validate_entries(entries)
            vault = Vault(fd, password, master, entries)
            yield vault
        finally:
            entries.clear()
            master[:] = b"\0" * len(master)
            if "vault" in locals():
                vault.password = None
