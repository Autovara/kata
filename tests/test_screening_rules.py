"""Shared screening rules stay safe without imposing inference policy."""

from __future__ import annotations

from kata.screening.rules import screen_bundle_static_policy


def _agent(source: str) -> dict[str, str]:
    return {"agent.py": source}


def test_shared_screen_allows_miner_owned_inference_choices() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            'URL = "https://api.example-provider.test/v1"\n'
            "def agent_main():\n"
            "    request = {'model': 'miner/model', 'max_tokens': 999999}\n"
            "    call(temperature=0.7, top_p=0.9, retries=12)\n"
            "    return {'vulnerabilities': []}\n"
        )
    )

    assert not findings


def test_shared_screen_rejects_kata_platform_secret_access() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "import os\n"
            "def agent_main():\n"
            "    os.environ.get('KATA_VALIDATOR_API_KEY')\n"
            "    return {'vulnerabilities': []}\n"
        )
    )

    assert [finding.rule_id for finding in findings] == ["bundle.secret_env"]


def test_shared_screen_rejects_duplicate_agent_main() -> None:
    # A decoy-first + shadow-last pair must be rejected: screening validates the
    # first definition, but Python runs the last one at import time (#151).
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': []}\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_duplicate" for finding in findings)


def test_shared_screen_rejects_duplicate_agent_main_across_sync_and_async() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "async def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': []}\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_duplicate" for finding in findings)


def test_shared_screen_rejects_agent_main_rebound_by_assignment() -> None:
    # A single `def` passes the duplicate check, but the module-level assignment is what
    # the runner ends up calling -- screening validated a decoy it never executes.
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "def _canned(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': [{'file': 'X.sol'}]}\n"
            "agent_main = _canned\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_agent_main_shadowed_in_module_control_flow() -> None:
    # `if`/`try` bodies run at import time, so a nested def rebinds the global just as a
    # top-level duplicate does -- while sitting outside the module body the old check read.
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "if True:\n"
            "    def agent_main(project_dir=None, inference_api=None):\n"
            "        return {'vulnerabilities': []}\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_agent_main_rebound_by_import_alias() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "from helpers.canned import report as agent_main\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_agent_main_rebound_through_global_declaration() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "def _install():\n"
            "    global agent_main\n"
            "    agent_main = lambda project_dir=None, inference_api=None: {}\n"
            "_install()\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_decorated_agent_main() -> None:
    # A decorator returns whatever it likes, so the executed callable is not the
    # inspected body.
    findings = screen_bundle_static_policy(
        _agent(
            "def _swap(fn):\n"
            "    def replacement(project_dir=None, inference_api=None):\n"
            "        return {'vulnerabilities': [{'file': 'X.sol'}]}\n"
            "    return replacement\n"
            "@_swap\n"
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_decorated" for finding in findings)


def test_shared_screen_rejects_star_import_that_shadows_the_entrypoint() -> None:
    # A star import binds whatever the helper exports; here that is agent_main itself.
    findings = screen_bundle_static_policy(
        {
            "agent.py": (
                "from helpers.canned import *\n"
                "def agent_main(project_dir=None, inference_api=None):\n"
                "    return {'vulnerabilities': analyze(project_dir)}\n"
            ),
            "helpers/canned.py": (
                "def agent_main(project_dir=None, inference_api=None):\n"
                "    return {'vulnerabilities': [{'file': 'X.sol'}]}\n"
            ),
        }
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_allows_star_import_that_cannot_shadow_the_entrypoint() -> None:
    findings = screen_bundle_static_policy(
        {
            "agent.py": (
                "from helpers.util import *\n"
                "def agent_main(project_dir=None, inference_api=None):\n"
                "    return {'vulnerabilities': rank([])}\n"
            ),
            "helpers/util.py": "def rank(findings):\n    return findings\n",
        }
    )

    assert not findings


def test_shared_screen_rejects_agent_main_replaced_through_globals() -> None:
    # Namespace mutation never writes the name in a binding position, so the binding
    # count cannot see it -- but the runner still calls the replacement.
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "globals()['agent_main'] = lambda project_dir=None, inference_api=None: {}\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_globals_mutation_from_a_function_called_at_import() -> None:
    # `globals()` reaches the module namespace from any scope, so the check cannot stop
    # at module scope the way the def/assignment check does.
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "def _install():\n"
            "    globals()['agent_main'] = lambda project_dir=None, inference_api=None: {}\n"
            "_install()\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_helper_that_patches_the_agent_module() -> None:
    findings = screen_bundle_static_policy(
        {
            "agent.py": (
                "import helpers.patch\n"
                "def agent_main(project_dir=None, inference_api=None):\n"
                "    return {'vulnerabilities': analyze(project_dir)}\n"
            ),
            "helpers/patch.py": (
                "import sys\n"
                "setattr(sys.modules['agent'], 'agent_main', lambda *a, **k: {})\n"
            ),
        }
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_rejects_agent_main_installed_through_exec() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "exec('agent_main = lambda project_dir=None, inference_api=None: {}')\n"
        )
    )

    assert any(finding.rule_id == "bundle.agent_main_rebound" for finding in findings)


def test_shared_screen_allows_namespace_writes_that_cannot_reach_the_entrypoint() -> None:
    # A constant key other than the entrypoint provably cannot rebind it; only computed
    # keys (which are unknowable here) fail closed.
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': analyze(project_dir)}\n"
            "globals()['CACHE'] = {}\n"
            "globals().update(TIMEOUT=30)\n"
            "exec('TOTAL = 1 + 1')\n"
        )
    )

    assert not findings


def test_shared_screen_allows_nested_and_method_definitions_named_agent_main() -> None:
    # Only MODULE-scope bindings can replace the entrypoint; a method or a def inside
    # another function binds in its own scope and must not be flagged.
    findings = screen_bundle_static_policy(
        _agent(
            "class Scanner:\n"
            "    def agent_main(self):\n"
            "        return None\n"
            "def _build():\n"
            "    def agent_main():\n"
            "        return 1\n"
            "    return agent_main()\n"
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': [_build()]}\n"
        )
    )

    assert not findings


def test_shared_screen_allows_single_agent_main() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': []}\n"
        )
    )

    assert not any(finding.rule_id == "bundle.agent_main_duplicate" for finding in findings)
