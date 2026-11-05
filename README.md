# sfm — Secure File Manager

ICS0022 Secure Programming, checkpoint 2. A local Linux CLI that encrypts files
and their names in a password-protected vault. Python 3.11+, PyCryptodome,
AES-256-GCM and scrypt. No network service or GUI.

## Install and run

On a clean Linux machine, install Python 3.11+ with pip and venv support
(on Debian/Ubuntu: `sudo apt install python3 python3-venv python3-pip`).
Extract this repository, open a terminal in its root, then:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
sfm --help
python -m pytest -q
```

`python -m sfm` is equivalent to `sfm`. A normal terminal is required for hidden
password input; redirected input without a controlling terminal is rejected.
Choose a master passphrase of 12–1024 characters. There is no password recovery.

```bash
sfm --vault ./demo.vault init
printf 'example contents\n' > sample.txt
sfm --vault ./demo.vault add sample.txt --as notes.txt
sfm --vault ./demo.vault ls
sfm --vault ./demo.vault info notes.txt
sfm --vault ./demo.vault get notes.txt restored.txt
cmp sample.txt restored.txt
sfm --vault ./demo.vault verify
```

Every command except help/version prompts for the master password. Initialization
and password changes ask for confirmation. Passwords are never arguments or
printed; file contents are exported to a file, never displayed by the CLI.
Imported source files remain on disk in their original form.

## Commands

Put `--vault PATH` **before** the command; the default is `~/.sfm-vault`.
The vault's parent directory must already exist. `init` refuses an existing path.

| Command | Behaviour |
| --- | --- |
| `init` | Create a private vault and set its password |
| `add SRC [--as NAME]` | Import a regular file; reject duplicate names |
| `get NAME DEST [--force]` | Export after authentication; refuse overwrite by default |
| `ls [PREFIX]` | List matching logical names |
| `info NAME` | Show byte size and UTC timestamps |
| `mv OLD NEW` | Rename without replacing another entry |
| `rm NAME` | Remove an entry |
| `verify` | Authenticate the whole vault and validate every entry |
| `passwd` | Change the password, keeping the master key |
| `rekey` | Generate a new master key and re-encrypt the vault |

Logical names are 1–255 printable characters without `/` or `\`; `.` and `..`
are rejected. Quote paths containing spaces; use `--` before positional paths
starting with `-`. Exit codes: 0 success, 1 operation failure, 2 argument error.

## Storage and limits

The vault directory is mode 0700; `vault.json` is mode 0600. Its public envelope
contains the version, salt, fixed scrypt parameters, encrypted master key and
ciphertexts. Names, contents, sizes and timestamps are encrypted together.
Never manually edit these files. Back up the complete vault while no command is
running; test the copy with `verify` before relying on it.

Files are limited to 8 MiB; the serialized encrypted vault is limited to 32 MiB.
The entire vault is authenticated and loaded in memory for each command. Each
save rewrites it atomically; commands use an exclusive directory lock. This is
the bounded checkpoint 2 format, not the planned chunked object store.

Use trusted parent directories. Final path components are opened without following
symlinks; special files and multiply linked source/vault files are rejected.
Exports inside the vault are rejected. Exports are plaintext mode 0600 files;
`--force` replaces an existing regular file. Deletion and password changes cannot
erase old filesystem snapshots or backups.

This educational implementation does not protect an unlocked process from
malware/root, guarantee memory erasure, detect whole-vault rollback, or enforce
a persistent password-attempt limit. Scrypt uses about 128 MiB per derivation;
leave additional RAM available for the vault and Python process. Windows/macOS
are outside scope.

## Repository

- `src/sfm/`: CLI, cryptography, storage and vault operations.
- `tests/`: functional and security regression tests.
- [Current design](docs/DESIGN.md): architecture and implemented mitigations.
- [Progress note](docs/PROGRESS.md): checkpoint coverage, validation and limits.
- `docs/checkpoint1/`: original design and diagram, retained as historical material.
