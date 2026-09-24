# sfm: Secure File Manager

ICS0022 Secure Programming, final project. A command-line file manager that stores files in a password-protected **encrypted vault** (AES-256-GCM, scrypt) on Linux, written in Python.

> Status: **Checkpoint 1** (design and threat model). Commands below are planned; the CLI skeleton exists but they are not implemented yet.

## Scope

**In scope:** create a vault; import, list, export, rename and delete files inside it; confidentiality and integrity of file contents and names; safe handling of file paths, permissions and races; password and key management (change password, rotate key).

**Out of scope:** network or multi-user sharing, GUI, Windows/macOS, protection against a root attacker or malware on a running, unlocked session, rollback of a whole vault to an older snapshot.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the architecture diagram, threat model and library choices.

## Planned commands

Global option: `--vault PATH` (default `~/.sfm-vault`). The password is always prompted, never passed as an argument.

| Command | Purpose |
|---------|---------|
| `sfm init` | Create a new vault and set the password |
| `sfm add SRC [--as NAME]` | Encrypt and import a file |
| `sfm get NAME DEST [--force]` | Decrypt and export a file (refuses to overwrite by default) |
| `sfm ls [PREFIX]` | List files in the vault |
| `sfm info NAME` | Show size and timestamps |
| `sfm mv OLD NEW` | Rename a file inside the vault |
| `sfm rm NAME` | Delete a file from the vault |
| `sfm verify` | Check integrity of header, index and all objects |
| `sfm passwd` | Change the password (re-wraps the master key) |
| `sfm rekey` | Rotate the master key and re-encrypt all files |

## Build and run

Requires Linux and Python 3.11+. Uses PyCryptodome.

```bash
git clone https://github.com/us3rop/secprog secure-file-manager && cd secure-file-manager
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

sfm --help          # or: python -m sfm --help
pytest              # run tests
```

## Layout

```
src/sfm/     application code (cli.py now; pathguard, keys, crypto, index, storage planned)
tests/       pytest tests
docs/        DESIGN.md, architecture diagram
```

