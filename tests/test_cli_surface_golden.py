"""The CLI surface, frozen.

`kata` is invoked as a SUBPROCESS by kata-bot, which parses its stdout. The parser is therefore a
cross-project contract, not an internal detail: a renamed flag, a changed default, or a command that
quietly stops existing breaks a separately deployed consumer, and it breaks it on a paid round.

Captured before the Phase 2 split of `cli.py` so that "parser construction moved, behaviour did not"
is a checkable claim. Regenerate deliberately with GOLDEN_UPDATE=1 and read the diff.
"""

from __future__ import annotations

import os
from pathlib import Path

from kata.cli import build_parser

GOLDEN = Path(__file__).resolve().parent / "golden" / "cli-help.txt"


def _render() -> str:
    parser = build_parser()
    subs = next(a for a in parser._actions if hasattr(a, "choices") and a.choices)
    lines = ["### kata --help\n" + parser.format_help()]
    for name in sorted(subs.choices):
        command = subs.choices[name]
        lines.append(f"### kata {name} --help\n{command.format_help()}")
        nested = next((a for a in command._actions if hasattr(a, "choices") and a.choices), None)
        if nested:
            for sub_name in sorted(nested.choices):
                lines.append(
                    f"### kata {name} {sub_name} --help\n{nested.choices[sub_name].format_help()}")
    return "\n".join(lines)


def test_the_cli_surface_is_unchanged():
    actual = _render()
    if os.environ.get("GOLDEN_UPDATE") == "1" or not GOLDEN.is_file():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(actual)
        return
    assert actual == GOLDEN.read_text(), (
        "the kata CLI surface changed. kata-bot invokes this parser as a subprocess and is deployed "
        "separately, so a change here reaches a running consumer before any coordinated release. "
        "If deliberate, rerun with GOLDEN_UPDATE=1 and review the diff."
    )


def test_every_command_the_bot_invokes_still_exists():
    """Named explicitly rather than derived: these are the entry points kata-bot shells out to, and
    a golden diff would report their removal as one line among many."""
    parser = build_parser()
    subs = next(a for a in parser._actions if hasattr(a, "choices") and a.choices)
    assert "challenge" in subs.choices
    challenge = subs.choices["challenge"]
    flags = {option for action in challenge._actions for option in action.option_strings}
    for required in ("--evaluator", "--king-path", "--candidate", "--output-root"):
        assert required in flags, f"kata challenge lost {required}, which kata-bot passes"


def test_the_deprecated_repo_pack_alias_is_retained():
    """Kept until the compatibility policy says otherwise. A repository search finding no caller is
    not evidence here: the callers are separately deployed, and an operator's saved command line is
    a caller too.

    Note the spelling. The refactoring order calls this a "--pack alias"; the option is actually
    ``--repo-pack``, and no ``--pack`` has ever existed in this repository's history. A cleanup that
    went looking for ``--pack`` would have found nothing and concluded the shim was already gone.
    """
    parser = build_parser()
    subs = next(a for a in parser._actions if hasattr(a, "choices") and a.choices)
    aliases = []
    for command in subs.choices.values():
        nested = next((a for a in command._actions if hasattr(a, "choices") and a.choices), None)
        targets = list(nested.choices.values()) if nested else [command]
        for target in targets:
            for action in target._actions:
                if "--repo-pack" in action.option_strings:
                    aliases.append((target.prog, action.dest))
    assert aliases, "the deprecated --repo-pack alias is gone"
    # It must still land on the same destination, or it is an alias in name only.
    assert all(dest == "subnet_pack" for _, dest in aliases), aliases
