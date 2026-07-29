"""The CLI surface, frozen.

`kata` is invoked as a SUBPROCESS by kata-bot, which parses its stdout. The parser is therefore a
cross-project contract, not an internal detail: a renamed flag, a changed default, or a command that
quietly stops existing breaks a separately deployed consumer, and it breaks it on a paid round.

WHAT THIS RECORDS, AND WHY IT IS NOT `--help` TEXT.

The first two versions compared `parser.format_help()`. Both were wrong, and each failure looked
like a real one:

* argparse wraps usage lines to the terminal width, so the golden recorded the width of whichever
  machine captured it. Pinning ``COLUMNS`` fixed that.
* argparse's usage-wrapping ALGORITHM then changed between Python 3.12 and 3.13. This project
  supports both (``requires-python = ">=3.12"``), so no single rendering is correct on both. CI ran
  3.12 against a golden captured on 3.13 and produced a red build whose entire diff was re-wrapped
  usage lines, with every option list identical.

Neither failure was a change to the CLI. Wrapping is presentation; the contract is the set of
commands, their flags, and what those flags do. So this records the parser's STRUCTURE -- names,
option strings, destinations, defaults, requiredness, choices, nargs, and the unwrapped help string.

That is both stricter and quieter: a renamed flag or a changed default is one obvious line, and
reflowing is not a line at all.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from kata.cli import build_parser

GOLDEN = Path(__file__).resolve().parent / "golden" / "cli-surface.json"


def _subparsers_action(parser: argparse.ArgumentParser):
    return next((a for a in parser._actions if isinstance(a, argparse._SubParsersAction)), None)


def _describe_action(action: argparse.Action) -> dict:
    """One flag, as its contract rather than as its rendering."""
    default = action.default
    if not isinstance(default, (str, int, float, bool, type(None))):
        default = repr(default)
    return {
        "class": type(action).__name__,
        "choices": sorted(map(str, action.choices)) if action.choices else None,
        # A changed default silently changes behaviour for every caller that omits the flag.
        "default": default,
        "dest": action.dest,
        "help": action.help,
        "metavar": action.metavar,
        "nargs": action.nargs,
        "option_strings": list(action.option_strings),
        "required": bool(action.required),
        "type": getattr(action.type, "__name__", None) if action.type else None,
    }


def _describe_parser(parser: argparse.ArgumentParser) -> dict:
    subparsers = _subparsers_action(parser)
    return {
        "actions": [
            _describe_action(a)
            for a in sorted(parser._actions, key=lambda a: (a.dest, str(a.option_strings)))
            if not isinstance(a, argparse._SubParsersAction)
        ],
        "description": parser.description,
        "prog": parser.prog,
        "subcommands": {
            name: _describe_parser(sub)
            for name, sub in sorted((subparsers.choices or {}).items())
        } if subparsers else {},
    }


def _render() -> str:
    return json.dumps(_describe_parser(build_parser()), indent=2, sort_keys=True) + "\n"


def test_the_cli_surface_is_unchanged():
    actual = _render()
    if os.environ.get("GOLDEN_UPDATE") == "1" or not GOLDEN.is_file():
        GOLDEN.parent.mkdir(parents=True, exist_ok=True)
        GOLDEN.write_text(actual)
        return
    assert actual == GOLDEN.read_text(), (
        "the kata CLI surface changed. kata-bot invokes this parser as a subprocess and is "
        "deployed separately, so a change here reaches a running consumer before any coordinated "
        "release. If deliberate, rerun with GOLDEN_UPDATE=1 and review the diff."
    )


def test_the_surface_does_not_depend_on_terminal_width():
    """It must record the CLI, not the machine that ran it."""
    previous = os.environ.get("COLUMNS")
    renders = set()
    try:
        for width in ("40", "80", "120", "300"):
            os.environ["COLUMNS"] = width
            renders.add(_render())
        os.environ.pop("COLUMNS", None)
        renders.add(_render())
    finally:
        if previous is None:
            os.environ.pop("COLUMNS", None)
        else:
            os.environ["COLUMNS"] = previous
    assert len(renders) == 1, "the recorded CLI surface changed with the terminal width"


def test_the_surface_records_no_rendered_help_text():
    """A guard against reverting to ``format_help()``.

    Rendered help embeds argparse's wrapping, which differs by terminal width AND by interpreter
    version. Recording it makes this test fail for reasons that are not changes to the CLI -- and a
    test that cries wolf gets its golden regenerated without being read, which is the failure that
    actually costs something.
    """
    body = _render()
    # `usage:` only ever appears in rendered output. (`-h`'s HELP STRING is legitimately
    # "show this help message and exit" -- that is the contract, not the rendering, so it stays.)
    assert "usage:" not in body
    # Structural, not textual: it must parse and carry the parser's shape.
    document = json.loads(body)
    assert set(document) == {"actions", "description", "prog", "subcommands"}
    assert document["subcommands"], "the surface records no subcommands"


def test_every_command_the_bot_invokes_still_exists():
    """Named explicitly rather than derived: these are the entry points kata-bot shells out to, and
    a golden diff would report their removal as one line among many."""
    parser = build_parser()
    subs = _subparsers_action(parser)
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
    subs = _subparsers_action(parser)
    aliases = []
    for command in subs.choices.values():
        nested = _subparsers_action(command)
        targets = list(nested.choices.values()) if nested else [command]
        for target in targets:
            for action in target._actions:
                if "--repo-pack" in action.option_strings:
                    aliases.append((target.prog, action.dest))
    assert aliases, "the deprecated --repo-pack alias is gone"
    # It must still land on the same destination, or it is an alias in name only.
    assert all(dest == "subnet_pack" for _, dest in aliases), aliases
