"""`kata lane` — initialise, list and sync lanes."""

from __future__ import annotations

import argparse

from kata.cli.output import print_json
from kata.state.lanes import (
    LANE_METADATA_SCHEMA_VERSION,
    EvaluatorLaneMetadata,
    lane_metadata_path,
    load_lane_metadata,
    load_pack_registry,
    sync_pack_registry,
    write_lane_metadata,
)


def handle_lane_init(args: argparse.Namespace) -> int:
    from datetime import UTC, datetime

    now = datetime.now(UTC).isoformat()
    created_at = now
    if lane_metadata_path(args.lane_id, public_root=args.public_root).exists():
        created_at = load_lane_metadata(args.lane_id, public_root=args.public_root).created_at
    metadata = EvaluatorLaneMetadata(
        schema_version=LANE_METADATA_SCHEMA_VERSION,
        lane_id=args.lane_id,
        subnet_pack=args.subnet_pack or args.lane_id,
        mode=args.mode,
        evaluator_id=args.evaluator_id,
        evaluator_policy_version=args.policy_version,
        active=not args.inactive,
        created_at=created_at,
        updated_at=now,
    )
    path = write_lane_metadata(metadata, public_root=args.public_root)
    if args.json:
        print_json({"lane_metadata_path": str(path), "lane_id": metadata.lane_id})
    else:
        print(f"Registered lane `{metadata.lane_id}` at {path}")
    return 0


def handle_lane_list(args: argparse.Namespace) -> int:
    registry = load_pack_registry(public_root=args.public_root)
    packs = [pack for pack in registry.packs if pack.active or not args.active_only]
    if args.json:
        print_json(
            {
                "schema_version": registry.schema_version,
                "updated_at": registry.updated_at,
                "packs": [
                    {
                        "lane_id": pack.lane_id,
                        "subnet_pack": pack.subnet_pack,
                        "mode": pack.mode,
                        "evaluator_id": pack.evaluator_id,
                        "active": pack.active,
                    }
                    for pack in packs
                ],
            }
        )
        return 0
    if not packs:
        print("No subnet packs registered.")
        return 0
    for pack in packs:
        status = "active" if pack.active else "inactive"
        print(f"{pack.lane_id}  mode={pack.mode}  evaluator={pack.evaluator_id}  {status}")
    return 0


def handle_lane_sync_registry(args: argparse.Namespace) -> int:
    registry = sync_pack_registry(public_root=args.public_root)
    if args.json:
        print_json(
            {
                "packs": [pack.lane_id for pack in registry.packs],
                "updated_at": registry.updated_at,
            }
        )
    else:
        print(f"Synced pack registry with {len(registry.packs)} lane(s).")
    return 0
