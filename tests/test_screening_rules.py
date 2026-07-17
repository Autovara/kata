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


def test_shared_screen_allows_single_agent_main() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main(project_dir=None, inference_api=None):\n"
            "    return {'vulnerabilities': []}\n"
        )
    )

    assert not any(finding.rule_id == "bundle.agent_main_duplicate" for finding in findings)
