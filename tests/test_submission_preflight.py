"""Repository preflight behavior for each supported submission pack."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from kata.submissions import preflight

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
SEALED_KEY = "04" + "ab" * 120
NETWORKING_AGENT = (
    "import socket\n"
    "import urllib.request\n\n\n"
    "def agent_main(project_dir=None, inference_api=None):\n"
    "    return {'vulnerabilities': []}\n"
)


def _write_bundle(
    repository_root: Path,
    pack: str,
    submission_id: str,
    agent_source: str,
    *,
    sealed_key: str | None = SEALED_KEY,
) -> Path:
    # A competition repository carries the published policies. Building a temp root without them
    # made these tests exercise a repository shape production never has -- and the gate now
    # correctly refuses such a root, because it cannot tell what any pack allows.
    _publish_policies(repository_root)
    directory = (
        repository_root / "submissions" / pack / preflight.SUBMISSION_MODE / submission_id
    )
    directory.mkdir(parents=True)
    (directory / "agent.py").write_text(agent_source, encoding="utf-8")
    (directory / "agent_manifest.json").write_text(
        json.dumps({"schema_version": 1, "runtime": "python", "entrypoint": "agent.py"}) + "\n",
        encoding="utf-8",
    )
    (directory / "submission.json").write_text(
        json.dumps(
            {
                "schema_version": 2,
                "subnet_pack": pack,
                "mode": preflight.SUBMISSION_MODE,
                "submission_id": submission_id,
                "created_at": "2026-07-29T00:00:00Z",
                "author": "alice",
                "title": "t",
                "notes": "n",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    if sealed_key is not None:
        (directory / preflight.SEALED_KEY_FILENAME).write_text(
            sealed_key + "\n",
            encoding="utf-8",
        )
    return directory


def _publish_policies(repository_root: Path) -> None:
    """Copy the real published policies into a temp repository root."""
    source = REPOSITORY_ROOT / preflight.POLICIES_RELATIVE_PATH
    target = repository_root / preflight.POLICIES_RELATIVE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.exists():
        target.write_bytes(source.read_bytes())


def _check(directory: Path, repository_root: Path) -> list[str]:
    return preflight.check_submission(directory, repository_root=repository_root)


def _sn22_banned_tuple() -> tuple[str, ...] | None:
    """Read the actual local tuple iterated by SN22's static screen."""

    plugin = REPOSITORY_ROOT.parent / "kata-sn22" / "kata_sn22" / "plugin.py"
    if not plugin.is_file():
        return None
    tree = ast.parse(plugin.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "banned"
                   for target in node.targets):
            continue
        if not isinstance(node.value, (ast.Tuple, ast.List)):
            continue
        values = [
            element.value
            for element in node.value.elts
            if isinstance(element, ast.Constant) and isinstance(element.value, str)
        ]
        if values:
            return tuple(values)
    return None


PUBLISHED = preflight.load_pack_policies(REPOSITORY_ROOT)


@pytest.mark.contract
def test_the_published_policy_matches_sn22s_own_static_screen() -> None:
    """The engine no longer knows this list; the competition repo carries it as published data. It
    still has to equal what the subnet actually enforces, or the gate and the lane disagree about
    the same submission."""
    banned = _sn22_banned_tuple()
    if banned is None:
        pytest.skip("kata-sn22 is not checked out beside this repository")
    assert PUBLISHED["sn22__desearch"].banned_source_markers == banned


@pytest.mark.contract
def test_the_published_policy_matches_each_subnets_declaration() -> None:
    """Published from ``deploy/settings.json``; a hand edit to the published copy would make the
    competition repository disagree with the subnet whose contract it describes."""
    for pack, policy in PUBLISHED.items():
        subnet = pack.split("__")[0]
        settings = REPOSITORY_ROOT.parent / f"kata-{subnet}" / "deploy" / "settings.json"
        if not settings.is_file():
            pytest.skip(f"kata-{subnet} is not checked out beside this repository")
        # Named rather than indexed. This published a policy whose SOURCE was never committed:
        # `policies.json` was generated from a working-tree edit to the subnet's settings, so this
        # test passed locally and raised KeyError on any fresh clone -- a stack trace where the
        # answer is "kata-sn22 declares no submission_policy; commit it".
        declared = json.loads(settings.read_text(encoding="utf-8")).get("submission_policy")
        assert declared is not None, (
            f"{pack} is published in submissions/policies.json but kata-{subnet} declares no "
            f"submission_policy in deploy/settings.json. The published document is generated from "
            f"that declaration, so it cannot be committed without it"
        )
        assert list(policy.banned_source_markers) == declared["banned_source_markers"], pack
        assert bool(policy.banned_source_markers) != declared["direct_network_allowed"], pack


def test_the_engine_hardcodes_no_subnet_names() -> None:
    """The point of the move. A general framework must not carry a table of specific subnets: it is
    how the gate came to reject every correct SN60 agent (issue #209)."""
    source = (REPOSITORY_ROOT / "kata" / "submissions" / "preflight.py").read_text(encoding="utf-8")
    code = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#"))
    for name in ("sn60__bitsec", "sn22__desearch"):
        assert f'"{name}"' not in code, f"preflight.py still hardcodes {name}"


def test_an_undeclared_pack_gets_the_strictest_rule() -> None:
    """Fails closed. Applying a ban a pack does not want rejects honest submissions loudly; missing
    one it does need removes a guarantee silently."""
    strictest = preflight.strictest_policy(PUBLISHED)
    assert "urllib.request" in strictest.banned_source_markers
    assert "policies" in strictest.banned_source_reason


# --- what happens when the policy document cannot be trusted -------------------------------------
#
# These test the CLI EXIT STATUS, not the loader's return value. The previous version of this test
# asserted `load_pack_policies(tmp_path) == {}` under the name
# "a missing policy document does not wave submissions through" -- the name stated the safety
# property and the body asserted the exact value that violated it. `{}` meant no known packs, and
# discovery then iterated those keys, so `--all` found nothing, printed "no submissions found" and
# exited 0 with an unchecked agent in the tree. The test passed throughout.
#
# The lesson is the assertion target. `--all` is what `validate-submission.yml` runs, so `--all`'s
# exit status is the property that matters; everything else is an implementation detail that was
# free to be wrong.

BAD_DOCUMENTS = {
    "not json at all": "{not json",
    "top level is a list": "[]",
    "wrong schema version": '{"schema_version": 99, "policies": {"a__b": {}}}',
    "policies is a list": '{"schema_version": 1, "policies": [1, 2]}',
    "policies is empty": '{"schema_version": 1, "policies": {}}',
    "pack name is not a pack": '{"schema_version": 1, "policies": {"../etc": '
    '{"banned_source_markers": ["x"], "banned_source_reason": "r", '
    '"direct_network_allowed": false}}}',
    "entry is not an object": '{"schema_version": 1, "policies": {"a__b": "nope"}}',
    "direct_network_allowed missing": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": ["x"], "banned_source_reason": "r"}}}',
    "direct_network_allowed is a string": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": ["x"], "banned_source_reason": "r", '
    '"direct_network_allowed": "false"}}}',
    # The dangerous one: a bare string is iterable, so a laxer loader banned six single letters.
    "markers are a bare string": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": "urllib", "banned_source_reason": "r", '
    '"direct_network_allowed": false}}}',
    "a marker is an int": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": [42], "banned_source_reason": "r", '
    '"direct_network_allowed": false}}}',
    "a marker is empty": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": [""], "banned_source_reason": "r", '
    '"direct_network_allowed": false}}}',
    "allows the network yet bans markers": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": ["x"], "banned_source_reason": "r", '
    '"direct_network_allowed": true}}}',
    "forbids the network yet bans nothing": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": [], "banned_source_reason": "", '
    '"direct_network_allowed": false}}}',
    # MIXED documents. These are the ones a lenient loader survives: every single-fault case above
    # is also caught by some other rule, so dropping the bad element still fails the document and a
    # skip-the-bad-entry loader looks correct. Here the good part is enough to satisfy every other
    # rule, so only marker-level and entry-level validation can reject them. Discovered by planting
    # the lenient loader and finding the suite still green.
    "one marker among several is an int": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": ["import socket", 42], "banned_source_reason": "r", '
    '"direct_network_allowed": false}}}',
    "one pack among several is malformed": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": ["import socket"], "banned_source_reason": "r", '
    '"direct_network_allowed": false}, "c__d": "nope"}}',
    "bans markers without a reason": '{"schema_version": 1, "policies": {"a__b": '
    '{"banned_source_markers": ["x"], "banned_source_reason": "", '
    '"direct_network_allowed": false}}}',
}


@pytest.mark.parametrize("description", sorted(BAD_DOCUMENTS))
def test_an_invalid_policy_document_is_rejected_as_a_whole(
    tmp_path: Path, description: str
) -> None:
    """No partial acceptance. A document that is invalid anywhere yields no policies at all, because
    enforcing some rules while believing you enforced all of them is the failure that hides."""
    _publish_policies(tmp_path)
    (tmp_path / preflight.POLICIES_RELATIVE_PATH).write_text(
        BAD_DOCUMENTS[description], encoding="utf-8"
    )
    with pytest.raises(preflight.PolicyDocumentError):
        preflight.load_pack_policies(tmp_path)


@pytest.mark.parametrize("description", sorted(BAD_DOCUMENTS))
def test_an_invalid_policy_document_fails_the_all_run(
    tmp_path: Path, description: str, capsys: pytest.CaptureFixture[str]
) -> None:
    """The property CI depends on: a gate that cannot read its rules must not report success."""
    _write_bundle(
        tmp_path, "sn60__bitsec", "alice-20260729-11", "def agent_main():\n    return {}\n"
    )
    (tmp_path / preflight.POLICIES_RELATIVE_PATH).write_text(
        BAD_DOCUMENTS[description], encoding="utf-8"
    )
    assert preflight.main(["--all"], repository_root=tmp_path) != 0
    assert "cannot check submissions" in capsys.readouterr().out


def test_a_missing_policy_document_fails_the_all_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """Reproduces the reported defect directly: rc was 0 and the output was "no submissions found",
    with a banned-import agent sitting unchecked in the tree."""
    _write_bundle(tmp_path, "sn22__desearch", "alice-20260729-12", NETWORKING_AGENT)
    (tmp_path / preflight.POLICIES_RELATIVE_PATH).unlink()
    assert preflight.main(["--all"], repository_root=tmp_path) != 0
    output = capsys.readouterr().out
    assert "no submissions found" not in output
    assert "cannot check submissions" in output


def test_an_empty_repository_is_not_an_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The distinction the old code could not make. Nothing submitted is legitimate; rules that will
    not load is not. Without this, a fix for the above could fail everything and look correct."""
    _publish_policies(tmp_path)
    assert preflight.main(["--all"], repository_root=tmp_path) == 0
    assert "no submissions found" in capsys.readouterr().out


def test_discovery_does_not_depend_on_the_policy_document(tmp_path: Path) -> None:
    """Discovery answers "what was submitted" -- a question about the tree. Deriving it from policy
    keys is what made an undeclared pack's submissions invisible rather than rejected."""
    _write_bundle(tmp_path, "sn99__undeclared", "alice-20260729-13", NETWORKING_AGENT)
    assert preflight.discover_submissions(tmp_path)

    (tmp_path / preflight.POLICIES_RELATIVE_PATH).unlink()
    assert preflight.discover_submissions(tmp_path), "discovery consulted the policy document"


def test_a_submission_under_an_undeclared_pack_is_rejected_not_ignored(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """It used to exit 0 with "no submissions found"."""
    _write_bundle(tmp_path, "sn99__undeclared", "alice-20260729-14", NETWORKING_AGENT)
    assert preflight.main(["--all"], repository_root=tmp_path) == 1
    output = capsys.readouterr().out
    assert "sn99__undeclared" in output
    # Both the unknown name AND the strictest source rule, not merely the name.
    assert "urllib.request" in output


def test_sn60_may_reach_the_inference_gateway(tmp_path: Path) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-01",
        NETWORKING_AGENT,
    )
    assert _check(directory, tmp_path) == []


def test_reigning_sn60_king_passes(tmp_path: Path) -> None:
    king = REPOSITORY_ROOT / "kings" / "sn60__bitsec" / "miner" / "agent.py"
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-02",
        king.read_text(encoding="utf-8"),
    )
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("marker", PUBLISHED["sn22__desearch"].banned_source_markers)
def test_sn22_may_not_reach_providers_directly(tmp_path: Path, marker: str) -> None:
    source = f"{marker}\n\n\ndef agent_main():\n    return {{}}\n"
    directory = _write_bundle(
        tmp_path,
        "sn22__desearch",
        "bob-20260729-01",
        source,
    )
    problems = _check(directory, tmp_path)
    assert any(marker in problem for problem in problems), problems


def test_sn22_network_refusal_explains_the_supported_path(tmp_path: Path) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn22__desearch",
        "bob-20260729-02",
        NETWORKING_AGENT,
    )
    problems = _check(directory, tmp_path)
    assert any(
        "sn22__desearch" in problem and "broker capability" in problem
        for problem in problems
    )


def test_reigning_sn22_king_passes(tmp_path: Path) -> None:
    king = REPOSITORY_ROOT / "kings" / "sn22__desearch" / "miner" / "agent.py"
    directory = _write_bundle(
        tmp_path,
        "sn22__desearch",
        "carol-20260729-01",
        king.read_text(encoding="utf-8"),
    )
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("pack", sorted(PUBLISHED))
def test_production_four_file_bundle_is_accepted(tmp_path: Path, pack: str) -> None:
    directory = _write_bundle(
        tmp_path,
        pack,
        "alice-20260729-03",
        "def agent_main():\n    return {'vulnerabilities': []}\n",
    )
    assert sorted(path.name for path in directory.iterdir()) == [
        "agent.py",
        "agent_manifest.json",
        "sealed_inference_key",
        "submission.json",
    ]
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("pack", sorted(PUBLISHED))
def test_unexpected_top_level_file_is_rejected(tmp_path: Path, pack: str) -> None:
    directory = _write_bundle(
        tmp_path,
        pack,
        "alice-20260729-04",
        "def agent_main():\n    return {}\n",
    )
    (directory / "notes.txt").write_text("hello", encoding="utf-8")
    problems = _check(directory, tmp_path)
    assert any("unexpected top-level entry 'notes.txt'" in problem for problem in problems)


def test_three_file_bundle_remains_a_valid_layout(tmp_path: Path) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-05",
        "def agent_main():\n    return {}\n",
        sealed_key=None,
    )
    assert _check(directory, tmp_path) == []


@pytest.mark.parametrize("pack", sorted(PUBLISHED))
def test_shared_source_checks_still_apply_to_every_pack(tmp_path: Path, pack: str) -> None:
    directory = _write_bundle(
        tmp_path,
        pack,
        "alice-20260729-06",
        "def agent_main(:\n",
    )
    problems = _check(directory, tmp_path)
    assert any("syntax error" in problem for problem in problems)


def test_module_cli_discovers_submissions(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    directory = _write_bundle(
        tmp_path,
        "sn60__bitsec",
        "alice-20260729-07",
        "def agent_main():\n    return {}\n",
    )
    assert preflight.main(["--all"], repository_root=tmp_path) == 0
    assert f"ok    {directory.relative_to(tmp_path)}" in capsys.readouterr().out
