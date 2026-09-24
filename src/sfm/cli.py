"""Command-line interface (skeleton for Checkpoint 1).

Rules for this layer (see docs/DESIGN.md): the password is read with getpass
only, never from argv or the environment; errors are short and never leak
secrets; every path is handed to the Path Guard, never used directly.
"""
import argparse
import sys

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


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    print(f"sfm {args.command}: not implemented yet (Checkpoint 2)", file=sys.stderr)
    return EXIT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
