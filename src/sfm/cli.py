"""Command dispatch and hidden password prompts; never display file contents."""
import argparse
import sys
import getpass
import resource
import warnings
from pathlib import Path

from Crypto.Random import get_random_bytes
from sfm import storage
from sfm.crypto import VaultError, decode
from sfm.vault import initialize, unlock, timestamp

from sfm import __version__

EXIT_OK, EXIT_ERROR, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sfm", description="Secure File Manager (encrypted vault)")
    p.add_argument("--version", action="version", version=f"sfm {__version__}")
    p.add_argument("--vault", default="~/.sfm-vault", help="vault directory")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="create a new vault")
    a = sub.add_parser("add", help="encrypt and import a file")
    a.add_argument("src")
    a.add_argument("--as", dest="name", help="logical name inside the vault")
    g = sub.add_parser("get", help="decrypt and export a file")
    g.add_argument("name")
    g.add_argument("dest")
    g.add_argument("--force", action="store_true", help="replace an existing destination")
    ls = sub.add_parser("ls", help="list files")
    ls.add_argument("prefix", nargs="?", default="")
    sub.add_parser("info", help="show file details").add_argument("name")
    m = sub.add_parser("mv", help="rename a file in the vault")
    m.add_argument("old")
    m.add_argument("new")
    sub.add_parser("rm", help="delete a file from the vault").add_argument("name")
    sub.add_parser("verify", help="check vault integrity")
    sub.add_parser("passwd", help="change the password")
    sub.add_parser("rekey", help="rotate the master key")
    return p


def prompt(label="Master password: "):
    # Refuse getpass's echoing fallback when no secure terminal is available.
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        return getpass.getpass(label)


def new_password():
    password = prompt("New master password: ")
    if not 12 <= len(password) <= 1024:
        raise VaultError("master password must be 12–1024 characters")
    if password != prompt("Confirm master password: "):
        raise VaultError("passwords do not match")
    return password


def dispatch(args):
    path = Path(args.vault).expanduser().absolute()
    if args.command == "init":
        initialize(path, new_password())
        print("Vault created.")
        return
    with unlock(path, prompt()) as vault:
        if args.command == "add":
            vault.add(args.src, args.name)
        elif args.command == "get":
            entry = vault.require(args.name)
            storage.export_file(args.dest, decode(entry["data"]), path, args.force)
        elif args.command == "ls":
            for name in sorted(vault.entries):
                if name.startswith(args.prefix):
                    print(name)
            return
        elif args.command == "info":
            entry = vault.require(args.name)
            for field in ("size", "created", "modified"):
                print(f"{field}: {entry[field]}")
            return
        elif args.command == "mv":
            from sfm.vault import validate_name
            entry = vault.require(args.old)
            validate_name(args.new)
            if args.new in vault.entries:
                raise VaultError("name already exists")
            vault.entries[args.new] = entry
            del vault.entries[args.old]
            entry["modified"] = timestamp()
            vault.save()
        elif args.command == "rm":
            vault.require(args.name)
            del vault.entries[args.name]
            vault.save()
        elif args.command == "passwd":
            vault.password = new_password()
            vault.save()
        elif args.command == "rekey":
            vault.master[:] = get_random_bytes(32)
            vault.save()
        elif args.command == "verify":
            print("Vault authenticated; all files verified.")
            return
    print("Done.")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        dispatch(args)
        return EXIT_OK
    except VaultError as error:
        print(f"sfm: {error}", file=sys.stderr)
    except (EOFError, KeyboardInterrupt, getpass.GetPassWarning):
        print("sfm: secure password input unavailable or cancelled", file=sys.stderr)
    except OSError:
        # OS errors can contain attacker-controlled paths; keep output constant.
        print("sfm: filesystem operation failed; check paths, permissions and available space", file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
