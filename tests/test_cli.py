import pytest

from sfm.cli import EXIT_ERROR, build_parser, main

COMMANDS = ["init", "add", "get", "ls", "info", "mv", "rm", "verify", "passwd", "rekey"]


def test_all_planned_commands_registered():
    choices = build_parser()._subparsers._group_actions[0].choices
    assert set(COMMANDS) <= set(choices)


def test_no_password_option():
    # Passwords must never be accepted on the command line (threat P3).
    assert "--password" not in build_parser().format_help()


def test_unimplemented_command_fails_cleanly():
    assert main(["verify"]) == EXIT_ERROR


def test_unknown_command_rejected():
    with pytest.raises(SystemExit):
        main(["frobnicate"])
