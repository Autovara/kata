#!/usr/bin/env bash
set -euo pipefail

workspace=${KATA_WORKSPACE:-}
agent_file=${KATA_AGENT_FILE:-}
task_file=${KATA_TASK_FILE:-}
model=${KATA_SOLVER_MODEL:-${KATA_LLM_MODEL:-}}
api_base=${KATA_SOLVER_API_BASE:-${KATA_LLM_API_BASE:-}}
api_key=${KATA_SOLVER_API_KEY:-${KATA_LLM_API_KEY:-}}

: "${workspace:?KATA_WORKSPACE is required}"
: "${agent_file:?KATA_AGENT_FILE is required}"
: "${task_file:?KATA_TASK_FILE is required}"

python3 - <<'PY'
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path


def load_agent_module(agent_path: Path):
    spec = importlib.util.spec_from_file_location("kata_submission_agent", agent_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load agent module: {agent_path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(agent_path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


def apply_patch(repo_path: Path, patch_text: str) -> None:
    normalized = patch_text.strip()
    if not normalized:
        return
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as handle:
        handle.write(normalized + "\n")
        patch_path = Path(handle.name)
    try:
        completed = subprocess.run(
            ["git", "apply", "--whitespace=nowarn", str(patch_path)],
            cwd=str(repo_path),
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(completed.stderr.strip() or "git apply failed")
    finally:
        patch_path.unlink(missing_ok=True)


workspace = Path(os.environ["KATA_WORKSPACE"]).resolve()
agent_path = Path(os.environ["KATA_AGENT_FILE"]).resolve()
task_path = Path(os.environ["KATA_TASK_FILE"]).resolve()
issue = task_path.read_text(encoding="utf-8")
model = (
    os.environ.get("KATA_SOLVER_MODEL")
    or os.environ.get("KATA_LLM_MODEL")
    or os.environ.get("KATA_LLM_MODEL", "")
)
api_base = (
    os.environ.get("KATA_SOLVER_API_BASE")
    or os.environ.get("KATA_LLM_API_BASE")
    or os.environ.get("KATA_LLM_API_BASE", "")
)
api_key = (
    os.environ.get("KATA_SOLVER_API_KEY")
    or os.environ.get("KATA_LLM_API_KEY")
    or os.environ.get("KATA_LLM_API_KEY", "")
)

module = load_agent_module(agent_path)
solve = getattr(module, "solve", None)
if solve is None or not callable(solve):
        raise RuntimeError(
            "agent.py must define callable solve(repo_path, issue, model, api_base, api_key)"
        )

result = solve(
    repo_path=str(workspace),
    issue=issue,
    model=model,
    api_base=api_base,
    api_key=api_key,
)

if result is None:
    result = {}
if not isinstance(result, dict):
    raise RuntimeError("solve(...) must return a dict")

patch_text = result.get("patch") or result.get("diff") or ""
if patch_text:
    apply_patch(workspace, str(patch_text))

message = str(result.get("message") or "").strip()
if message:
    print(message)
print(json.dumps({"success": bool(result.get("success", True))}))
PY
