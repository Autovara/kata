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
            "    findings = scan(request)\n"
            "    return {'vulnerabilities': findings}\n"
        )
    )

    assert not findings


def test_shared_screen_rejects_kata_platform_secret_access() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "import os\n"
            "def agent_main():\n"
            "    os.environ.get('KATA_VALIDATOR_API_KEY')\n"
            "    findings = scan()\n"
            "    return {'vulnerabilities': findings}\n"
        )
    )

    assert [finding.rule_id for finding in findings] == ["bundle.secret_env"]


def test_shared_screen_rejects_direct_empty_report() -> None:
    findings = screen_bundle_static_policy(
        _agent("def agent_main():\n    return {'vulnerabilities': []}\n")
    )

    assert [finding.rule_id for finding in findings] == ["bundle.no_op_report"]


def test_shared_screen_rejects_direct_constant_report() -> None:
    findings = screen_bundle_static_policy(
        _agent("def agent_main():\n    return {'vulnerabilities': [{'title': 'canned finding'}]}\n")
    )

    assert [finding.rule_id for finding in findings] == ["bundle.canned_report"]


def test_shared_screen_allows_dynamically_built_report() -> None:
    findings = screen_bundle_static_policy(
        _agent(
            "def agent_main():\n"
            "    findings = []\n"
            "    for candidate in scan():\n"
            "        findings.append(candidate)\n"
            "    return {'vulnerabilities': findings}\n"
        )
    )

    assert not findings
