#!/usr/bin/env bash
set -euo pipefail

workspace=${KATA_WORKSPACE:-}
prompt_file=${KATA_PROMPT_FILE:-}
task_file=${KATA_TASK_FILE:-}
mode=${KATA_MODE:-contributor}
model=${KATA_CLAUDE_MODEL:-}

: "${workspace:?KATA_WORKSPACE is required}"
: "${prompt_file:?KATA_PROMPT_FILE is required}"
: "${task_file:?KATA_TASK_FILE is required}"

if ! command -v claude >/dev/null 2>&1; then
  echo "claude CLI is not installed or not on PATH" >&2
  exit 127
fi

combined_prompt=$(mktemp)
trap 'rm -f "$combined_prompt"' EXIT

cat > "$combined_prompt" <<EOF
You are running inside a Kata eval workspace.

Your job is to modify the repository in the current workspace so it satisfies the eval task.

Rules:
- Follow the repo-specific prompt exactly.
- Follow the eval task exactly.
- Keep the diff minimal and task-scoped.
- Do not edit files outside the task scope unless the task explicitly requires it.
- The Kata runner will execute the task's own checks after you stop.
- Do not spend time running repo validation commands unless the needed dependencies are already available.
- If a repo validation command is unavailable, skip it and finish the task-scoped edit.
- Do not print a long explanation. Apply the changes directly in the workspace.
- Stop once the workspace contains your final solution.

Mode: ${mode}
Workspace: ${workspace}

## Repo-Specific Prompt

EOF

cat "$prompt_file" >> "$combined_prompt"

cat >> "$combined_prompt" <<EOF

## Eval Task

EOF

cat "$task_file" >> "$combined_prompt"

claude_args=(
  --print
  --output-format text
  --permission-mode bypassPermissions
  --dangerously-skip-permissions
  --add-dir "$workspace"
)

if [[ -n "$model" ]]; then
  claude_args+=(--model "$model")
fi

(
  cd "$workspace"
  claude "${claude_args[@]}" < "$combined_prompt"
)
