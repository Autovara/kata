"""`kata king` — promote and bootstrap a lane's king."""

from __future__ import annotations

import argparse
from pathlib import Path

from kata.cli.output import print_json
from kata.promotion import bootstrap_lane_king, find_evaluator_pack_entry
from kata.submissions.workflow import promote_submission_result


def handle_king_promote(args: argparse.Namespace) -> int:
    if not args.submission_path:
        raise SystemExit(
            "--submission-path is required: pass the candidate submission directory to promote."
        )
    # Default to None (not cwd) so promotion resolves the public root the same way
    # `verify`/`decide` do — honoring KATA_ROOT — instead of silently writing kings/ +
    # lane state into whatever directory it's run in.
    public_root = str(Path(args.public_root).expanduser().resolve()) if args.public_root else None
    result = promote_submission_result(
        args.submission_path,
        args.challenge_run,
        public_root=public_root,
    )
    if args.json:
        print_json(
            {
                "lane_id": result.lane_id,
                "king_root": result.king_root,
                "current_king_submission_id": result.king.current_king_submission_id,
                "current_king_artifact_hash": result.king.current_king_artifact_hash,
                "promotion_timestamp": result.king.promotion_timestamp,
            }
        )
    else:
        print(
            f"Promoted `{result.king.current_king_submission_id}` "
            f"as king of lane `{result.lane_id}`."
        )
    return 0


def handle_king_bootstrap(args: argparse.Namespace) -> int:
    public_root = str(Path(args.public_root).expanduser().resolve()) if args.public_root else None
    entry = find_evaluator_pack_entry(
        args.subnet_pack,
        args.mode,
        public_root=public_root,
    )
    if entry is None:
        raise SystemExit(
            f"No evaluator-backed lane is registered for `{args.subnet_pack}/{args.mode}`."
        )
    result = bootstrap_lane_king(
        entry=entry,
        baseline_path=args.baseline_path,
        baseline_id=args.baseline_id,
        public_root=public_root,
        replace_existing=args.replace,
    )
    if args.json:
        print_json(
            {
                "lane_id": result.lane_id,
                "baseline_id": result.baseline_id,
                "king_root": result.king_root,
                "current_king_artifact_hash": result.king.current_king_artifact_hash,
            }
        )
    else:
        print(f"Seeded `{result.baseline_id}` as the baseline king of lane `{result.lane_id}`.")
    return 0
