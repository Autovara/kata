# `kata` public surfaces

Everything another project may depend on. A refactor may move code freely *behind* this list; it may
not change an entry here without changing every consumer named beside it.

Recorded before the Phase 0 refactor so that "nothing observable changed" is a checkable claim rather
than a hope. Derived from the reviewed revision; regenerate by re-reading the sources cited.

## Console script

| Command | Target |
| --- | --- |
| `kata` | `kata.cli:main` |

## Repository submission preflight

Branch protection and contributor documentation invoke:

```text
python -m kata.submissions.preflight
```

## CLI subcommands

`bootstrap`, `capacity-estimate`, `challenge`, `init`, `inspect-pr`, `king`, `lane`, `list`,
`plugin`, `preflight`, `promote`, `submission`, `sync-registry`, `validate`

`kata challenge` is the engine entry point the bot invokes as a subprocess. Its stdout JSON is a
cross-project contract — see `kata-bot/docs/public-surfaces.md`.

## Plugin discovery

Subnets are discovered through the **`kata.subnets`** entry-point group. Each subnet package declares
one entry pointing at its `SubnetPlugin`:

| Distribution | Name | Value |
| --- | --- | --- |
| `kata-sn22` | `sn22` | `kata_sn22:SN22_DESEARCH_PLUGIN` |
| `kata-sn60` | `sn60` | `kata_sn60:SN60_BITSEC_PLUGIN` |

The group name and the `SubnetPlugin` base class are the contract. Renaming either breaks every
subnet repository, which are versioned and deployed independently.

## Environment variables

| Variable | Meaning |
| --- | --- |
| `KATA_ROOT` | root of the competition tree (`lanes/`, `kings/`, `submissions/`, `runs/`) |
| `KATA_LIVE_STATUS_PATH` | where live challenge status is written |
| `KATA_SCREENING_REVIEW_MODE` | screening policy selector |
| `KATA_SCREENING_STRICT_REPLAY` | strict replay for recorded screening |
| `KATA_VALIDATOR_API_BASE`, `KATA_VALIDATOR_API_KEY`, `KATA_VALIDATOR_MODEL` | optional LLM review |

## File formats and paths

Written under `KATA_ROOT`, read by the bot and the board:

| Path | Owner |
| --- | --- |
| `lanes/registry.json` | lane registry the board reads |
| `lanes/<lane>/lane.json` | per-lane public record, incl. `active` |
| `lanes/<lane>/king.json` | king ledger (`seeded` marks an unearned first king) |
| `kings/<pack>/<mode>/` | king artifact bundle: `agent.py`, `agent_manifest.json`, `submission.json`, `sealed_inference_key`, `king.json` |
| `submissions/<pack>/<mode>/<id>/` | miner submission bundle |
| `runs/<run-id>/challenge_result.json` | challenge result JSON |

## Ownership note: `live-status.json`

Written by **kata-bot**, not by this engine. `kata/state/progress.py` is an engine-side writer with
no caller; it is retained because `KATA_LIVE_STATUS_PATH` is still exported into the child process
and the function merges rather than overwrites. See that module's docstring.

## Generated outputs

`challenge_result.json` and the king/lane records above. No network endpoints are served.
