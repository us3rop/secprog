"""Linux storage: restrictive permissions, directory locks and atomic writes."""
from contextlib import contextmanager
import fcntl
import os
from pathlib import Path
import stat
import uuid

from sfm.crypto import MAX_VAULT, VaultError

MAX_FILE = 8 * 1024 * 1024


def check_regular(fd, private=False):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise VaultError("expected a regular file with a single hard link")
    if private and (info.st_uid != os.getuid() or info.st_mode & 0o077):
        raise VaultError("vault files must be owned by you with permissions 0600")


def read_regular(path, limit, *, dir_fd=None, private=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    with os.fdopen(fd, "rb") as stream:
        check_regular(stream.fileno(), private)
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise VaultError("file exceeds size limit")
    return data


@contextmanager
def locked_vault(path, create=False):
    if create:
        path.mkdir(mode=0o700)  # Existing directories are never reinitialised.
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise VaultError("vault directory must be owned by you with permissions 0700")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield fd
    finally:
        os.close(fd)


def load(fd):
    return read_regular("vault.json", MAX_VAULT, dir_fd=fd, private=True)


def atomic_write(fd, name, data, *, overwrite=True):
    temporary = ".sfm-" + uuid.uuid4().hex
    try:
        out = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
        else:
            # Linking publishes a complete file without an overwrite race.
            os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=fd)
        except FileNotFoundError:
            pass


def export_file(destination, data, vault, force=False):
    destination = Path(destination).expanduser().absolute()
    if destination.resolve().is_relative_to(vault.resolve()):
        raise VaultError("export destination must be outside the vault")
    fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if force:
            try:
                info = os.stat(destination.name, dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                    raise VaultError("destination must be a regular file, not a link")
        atomic_write(fd, destination.name, data, overwrite=force)
    finally:
        os.close(fd)
