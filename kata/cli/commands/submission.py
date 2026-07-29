"""`kata submission` — initialise, validate and inspect a submission."""

from __future__ import annotations

import argparse

from kata.cli.output import collect_changed_paths
from kata.submissions.rendering import (
    render_pull_request_inspection,
    render_submission_json,
    render_submission_validation,
)
from kata.submissions.workflow import (
    init_submission,
    inspect_pull_request,
    validate_submission,
)


def handle_submission_init(args: argparse.Namespace) -> int:
    submission_dir = init_submission(
        subnet_pack=args.subnet_pack,
        mode=args.mode,
        submission_id=args.submission_id,
        output_root=args.output_root,
        author=args.author,
        title=args.title,
        notes=args.notes,
    )
    print(f"Created submission: {submission_dir}")
    return 0


def handle_submission_validate(args: argparse.Namespace) -> int:
    changed_paths = collect_changed_paths(args.changed_path, args.changed_path_file)
    result = validate_submission(
        args.path,
        changed_paths=changed_paths,
        repo_root=args.repo_root,
    )
    print(render_submission_json(result) if args.json else render_submission_validation(result))
    return 0 if result.is_valid else 2


def handle_submission_inspect(args: argparse.Namespace) -> int:
    result = inspect_pull_request(
        repo_root=args.repo_root,
        changed_paths=collect_changed_paths(args.changed_path, args.changed_path_file),
    )
    print(render_submission_json(result) if args.json else render_pull_request_inspection(result))
    return 0 if result.action == "evaluate" else 2
