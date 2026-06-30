from __future__ import annotations

from kata.repository import RepositoryContext, resolve_repository


def generate_baseline_prompt(repo_ref: str, mode: str) -> str:
    with resolve_repository(repo_ref) as repo:
        return generate_baseline_prompt_from_repository(repo, mode)


def generate_baseline_prompt_from_repository(repo: RepositoryContext, mode: str) -> str:
    title = f"{mode.capitalize()} Baseline Prompt: {repo.display_name}"
    lines: list[str] = []
    lines.append(f"# {title}")
    lines.append("")
    lines.append(f"Repo: `{repo.display_name}`")
    if repo.full_name:
        lines.append(f"GitHub: `{repo.full_name}`")
    lines.append("")
    lines.append("This is the generic baseline prompt used for Kata comparison.")
    lines.append("It is intentionally not repo-specialized.")
    lines.append("")
    if mode == "reviewer":
        lines.extend(render_reviewer_baseline())
    else:
        lines.extend(render_contributor_baseline())
    return "\n".join(lines)


def render_contributor_baseline() -> list[str]:
    return [
        "## Instructions",
        "- Understand the task before editing code or content.",
        "- Keep changes scoped to the requested problem.",
        "- Prefer small, reviewable diffs over broad cleanup.",
        "- Run the repo's relevant validation commands before proposing the final result.",
        "- Avoid touching unrelated or sensitive files unless the task clearly requires it.",
        "- Summarize what changed, why it changed, and what validation was run.",
        "",
        "## Output Expectations",
        "- Deliver a correct, minimal solution.",
        "- Do not invent repo rules that are not explicitly provided.",
        "- Call out missing information instead of guessing.",
        "- If validation cannot be run, say so clearly.",
    ]


def render_reviewer_baseline() -> list[str]:
    return [
        "## Instructions",
        "- Review whether the change solves the stated task.",
        "- Check whether the diff is scoped and understandable.",
        "- Check whether relevant validation appears to have been run.",
        "- Flag risky or sensitive file changes.",
        "- Flag missing evidence, unclear reasoning, or unsupported assumptions.",
        "",
        "## Output Expectations",
        "- Focus on correctness, scope, and validation.",
        "- Do not assume repo-specific rules that are not explicitly given.",
        "- If information is missing, state the uncertainty clearly.",
    ]
