"""What miners are told must match what the gate enforces.

Nothing here tests code. It tests the three documents a contributor actually reads -- the README,
CONTRIBUTING, and the pull-request template -- against each other and against the published
policies, because that is where they were last found to disagree:

* the README said "one open PR at a time" while CONTRIBUTING and the PR template said one per
  subnet. Both cannot be right, and the wrong one costs a contributor a closed PR.
* the PR template forbade `socket`, `requests`, `httpx` and `urllib` for *every* subnet, while the
  published SN60 policy allows direct networking. A miner who followed the checklist would have
  written a worse agent than the rules require, and one who ignored it was right to.

That second one is the failure mode this repository keeps having in a new place: a general framework
restating a specific subnet's rule, which then drifts from the subnet that owns it. The engine was
cleaned of hardcoded subnet policy; the checklist a miner reads still had it.

A full suite and 16 green smoke checks reported none of this, because no test read the prose.
"""

from __future__ import annotations

import re
from pathlib import Path

from kata.submissions import preflight

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
README = REPOSITORY_ROOT / "README.md"
CONTRIBUTING = REPOSITORY_ROOT / "CONTRIBUTING.md"
PR_TEMPLATE = REPOSITORY_ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md"
CONTRIBUTOR_DOCS = (README, CONTRIBUTING, PR_TEMPLATE)


def test_no_contributor_document_claims_one_open_pr_overall() -> None:
    """The rule is one open PR *per subnet*. Stating it unqualified is not a loose paraphrase -- it
    tells a miner competing in two subnets that their second entry is a violation, when it is
    exactly what the competition wants."""
    states_the_limit = re.compile(r"one open PR|one PR at a time", re.IGNORECASE)
    # The qualifier may sit anywhere in the sentence -- "one open PR per contributor, per subnet"
    # and "one open PR per subnet per contributor" are both correct.
    qualified = re.compile(r"per subnet|for this subnet|same subnet", re.IGNORECASE)
    checked = 0
    for document in CONTRIBUTOR_DOCS:
        text = document.read_text(encoding="utf-8")
        for number, line in enumerate(text.splitlines(), start=1):
            # "the one-open-PR rule" names the rule rather than restating it.
            if "one-open-PR" in line or not states_the_limit.search(line):
                continue
            checked += 1
            assert qualified.search(line), (
                f"{document.name}:{number} states the open-PR limit without qualifying it by "
                f"subnet: {line!r}"
            )
    assert checked, "no document states the open-PR limit; this guard would pass on silence"


def test_the_pr_template_does_not_hardcode_one_subnets_networking_rule() -> None:
    """Whether an agent may reach the network directly is the SUBNET's rule, published per pack in
    ``submissions/policies.json``. A checklist that names specific modules is a second copy of that
    rule in a general document, and it is already wrong for any pack that permits them."""
    text = PR_TEMPLATE.read_text(encoding="utf-8")
    permissive = [
        pack
        for pack, policy in preflight.load_pack_policies(REPOSITORY_ROOT).items()
        if not policy.banned_source_markers
    ]
    assert permissive, "no pack permits direct networking; this guard can no longer detect drift"
    for module in ("`socket`", "`requests`", "`httpx`", "`urllib`"):
        assert module not in text, (
            f"the PR template forbids {module} for every subnet, but {', '.join(permissive)} "
            f"permit(s) direct networking. State it as the subnet's rule; let preflight apply it"
        )


def test_no_contributor_document_names_a_subnet_that_is_not_published() -> None:
    """A pack named in prose but absent from the published policies is either a subnet that was
    removed and left behind, or a typo a miner will copy into a directory name."""
    published = set(preflight.load_pack_policies(REPOSITORY_ROOT))
    mentioned = set()
    for document in CONTRIBUTOR_DOCS:
        mentioned |= set(re.findall(r"\bsn\d+__[a-z0-9_]+", document.read_text(encoding="utf-8")))
    unknown = mentioned - published - {"sn60__bitsec"}  # the README's worked example
    assert not unknown, f"contributor docs name unpublished packs: {sorted(unknown)}"


def test_the_contributor_path_points_only_at_files_that_exist() -> None:
    """``submissions/README.md`` was deleted and CONTRIBUTING pointed at it. A dead link in the one
    document that tells a miner where to go is the whole onboarding path."""
    link = re.compile(r"\[[^\]]*\]\((?!https?:|#)([^)#]+)")
    for document in CONTRIBUTOR_DOCS:
        for target in link.findall(document.read_text(encoding="utf-8")):
            resolved = (document.parent / target).resolve()
            assert resolved.exists(), f"{document.name} links to missing {target}"
