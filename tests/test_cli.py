from pathlib import Path

import pytest

from sfm.cli import EXIT_ERROR, build_parser, main

PASSWORD = "correct horse battery staple"


@pytest.fixture
def cli(tmp_path, monkeypatch):
    vault = tmp_path / "vault"

    def run(*args, answers=(PASSWORD,)):
        responses = iter(answers)
        monkeypatch.setattr("sfm.cli.getpass.getpass", lambda _: next(responses))
        return main(["--vault", str(vault), *map(str, args)])

    assert run("init", answers=(PASSWORD, PASSWORD)) == 0
    return vault, run


def test_all_commands_registered():
    choices = build_parser()._subparsers._group_actions[0].choices
    assert set(choices) == {"init", "add", "get", "ls", "info", "mv", "rm", "verify", "passwd", "rekey"}
    assert "--password" not in build_parser().format_help()


def test_full_workflow(cli, tmp_path, capsys):
    vault, run = cli
    source, exported = tmp_path / "source.bin", tmp_path / "export.bin"
    content = b"private contents\x00\xff" * 100
    source.write_bytes(content)
    assert run("add", source, "--as", "secret.bin") == 0
    assert b"private contents" not in (vault / "vault.json").read_bytes()
    assert b"secret.bin" not in (vault / "vault.json").read_bytes()
    assert run("ls") == 0
    assert "secret.bin" in capsys.readouterr().out
    assert run("info", "secret.bin") == 0
    assert run("mv", "secret.bin", "renamed.bin") == 0
    assert run("get", "renamed.bin", exported) == 0
    assert exported.read_bytes() == content
    assert exported.stat().st_mode & 0o777 == 0o600
    assert run("verify") == 0
    assert run("rm", "renamed.bin") == 0
    assert run("get", "renamed.bin", tmp_path / "missing") == EXIT_ERROR
    assert "private contents" not in capsys.readouterr().out
    assert vault.stat().st_mode & 0o777 == 0o700
    assert (vault / "vault.json").stat().st_mode & 0o777 == 0o600


def test_wrong_password_never_exports_or_changes_vault(cli, tmp_path, capsys):
    vault, run = cli
    before = (vault / "vault.json").read_bytes()
    output = tmp_path / "output"
    assert run("get", "anything", output, answers=("wrong",)) == 1
    assert "wrong password or corrupted vault" in capsys.readouterr().err
    assert not output.exists()
    assert (vault / "vault.json").read_bytes() == before


def test_password_change_and_rekey(cli):
    _, run = cli
    new = "another long master password"
    assert run("passwd", answers=(PASSWORD, new, new)) == 0
    assert run("verify") == 1
    assert run("verify", answers=(new,)) == 0
    assert run("rekey", answers=(new,)) == 0
    assert run("verify", answers=(new,)) == 0


def test_duplicate_and_export_overwrite(cli, tmp_path):
    _, run = cli
    source = tmp_path / "source"
    source.write_bytes(b"hello")
    assert run("add", source) == 0
    source.write_bytes(b"new")
    assert run("add", source) == 1
    assert run("get", "source", source) == 1
    assert source.read_bytes() == b"new"
    assert run("get", "source", source, "--force") == 0
    assert source.read_bytes() == b"hello"


def test_reinitialization_is_non_destructive(cli):
    vault, run = cli
    original = (vault / "vault.json").read_bytes()
    assert run("init", answers=(PASSWORD, PASSWORD)) == 1
    assert (vault / "vault.json").read_bytes() == original


def test_unsafe_paths(cli, tmp_path):
    vault, run = cli
    source = tmp_path / "source"
    source.write_text("secret")
    link = tmp_path / "link"
    link.symlink_to(source)
    assert run("add", link) == 1
    assert run("add", tmp_path) == 1
    assert run("add", tmp_path / "absent") == 1
    assert run("add", source) == 0
    assert run("get", "source", link, "--force") == 1
    assert run("get", "source", vault / "vault.json", "--force") == 1
    assert source.read_text() == "secret"


def test_invalid_password_creation(tmp_path, monkeypatch):
    monkeypatch.setattr("sfm.cli.getpass.getpass", lambda _: "short")
    path = tmp_path / "vault"
    assert main(["--vault", str(path), "init"]) == 1
    assert not path.exists()


def test_unknown_command():
    with pytest.raises(SystemExit) as error:
        main(["not-a-command"])
    assert error.value.code == 2
