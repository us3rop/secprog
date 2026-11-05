# Checkpoint 2 progress — 5 November 2026

Implemented the file-manager checkpoint using the existing `sfm` package,
CLI names, Python and PyCryptodome choices. Comments describe security-relevant
operations briefly; this note and DESIGN.md describe the current implementation.

| Requirement | Delivered |
| --- | --- |
| CLI and file arguments | All ten planned commands work through `sfm` and `python -m sfm` |
| Encryption/decryption | Binary-safe import/export; AES-256-GCM encrypts contents and names |
| Authentication | Hidden master-password prompt; scrypt unwraps the master key; GCM verification precedes any plaintext export |
| First-level validation | Logical-name rules, bounded reads, regular-file checks, no final symlinks, hard-link rejection, safe export defaults |
| Clean installation | Python virtual-environment instructions and pinned direct dependencies in pyproject.toml |
| Incremental history | Import, implementation, regression-test and documentation commits; full `.git` directory included |

## Verification

On Linux with Python 3.12:

- `python -m pytest -q`: **37 passed**, using real scrypt parameters.
- Built `sfm-0.2.0` as a wheel and installed it with its runtime dependency in
  a separate empty virtual environment.
- Ran the installed `init`, `add`, `ls`, `get` and `verify` commands through a
  real pseudoterminal. Binary files round-tripped exactly; passwords were not echoed.
- Regression tests cover wrong passwords, key rotation and password changes,
  altered ciphertext/nonces/tags, malformed envelopes, forbidden KDF settings,
  path validation, symlinks/hard links/FIFOs, permissions, duplicate names,
  overwrite refusal, failed atomic writes, concurrent updates and empty files.

Python 3.11+ is the supported target; other interpreter versions were not run
in this environment. This is checkpoint-level testing, not an independent audit.

## Scope decisions and remaining work

The initial design proposed an encrypted index plus separate chunked objects.
Checkpoint 2 uses one bounded encrypted envelope: at most 8 MiB per source file
and 32 MiB for the serialized vault. This keeps authenticated storage and atomic
updates small enough to review. Large-file streaming, object storage and persistent
online throttling are deferred. Password changes currently rewrite the payload
as well as re-wrap the key; key rotation rewrites the entire vault.

Python cannot guarantee erasure of immutable password/key/plaintext copies.
The CLI disables core dumps and clears the mutable master-key buffer when leaving
a session. Running malware/root, rollback, secure deletion and compromised
ancestor directories remain outside the implemented protection.
