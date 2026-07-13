from __future__ import annotations

from helpers.analyze import merge_findings, rank_sources, static_findings, build_audit_prompt, parse_model_findings
from helpers.collect import collect_sources, resolve_project_root
from helpers.inference import call_model


def run_agent(project_dir: str | None, inference_api: str | None) -> dict:
    root = resolve_project_root(project_dir)
    if root is None:
        return {"vulnerabilities": []}

    sources = collect_sources(root)
    if not sources:
        return {"vulnerabilities": []}

    ranked = rank_sources(sources)
    heuristic_hits = static_findings(ranked)

    model_hits: list[dict] = []
    for item in ranked[:2]:
        response = call_model(inference_api, build_audit_prompt(item))
        model_hits.extend(parse_model_findings(response, item.rel))

    return {"vulnerabilities": merge_findings(heuristic_hits, model_hits)}
