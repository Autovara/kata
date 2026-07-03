# System Workflow

Kata is a PR-based miner-agent competition system.

The live system is split across repos:

- public `kata` — engine, pack registry, lane state, kings, submissions
- `kata-bot` — GitHub automation: webhook, queue, evaluation, merge, labels
- `kata-board` — dashboard reading lane state and live validator status
- pinned Bitsec `sandbox` mirror — SN60 evaluation harness

## Pack model

- the central pack registry (`lanes/registry.json`) lists subnet packs and
  their evaluator adapter ids
- each pack has isolated state under `lanes/<lane-id>/` and one current king
  under `kings/<subnet-pack>/<mode>/`
- the engine, bot, and board discover packs only through the registry

## Inference and cost

- Miners submit only an agent. The **validator** funds inference with two of its own
  keys: `INFERENCE_API_KEY` (OpenRouter) for the agent and `CHUTES_API_KEY` (Chutes)
  for scoring.
- Agents run on an internet-blocked Docker network and reach models only through the
  endpoint the validator provides (`KATA_SN60_INFERENCE_API`). Pointing that at the
  **model-pinning relay** forces every agent request onto one fixed model, so the
  duel is fair and the budget is protected.
- Two optional cost levers: the relay meters exact per-PR token spend (`/costs`), and
  two-phase early-stop can short-circuit a decisive candidate loss without ever
  shortcutting a promotion (see `docs/sn60-early-stop.md`).

## From PR to king

1. Miner opens one PR touching exactly one submission bundle.
2. `kata-bot` queues the PR and inspects changed paths.
3. Kata validates the bundle against the SN60 miner contract.
4. Screening: static checks plus one sandbox execution must pass.
5. Duel: candidate and king run repeated replicas per benchmark codebase in
   the pinned Bitsec sandbox.
6. Verification checks freshness against lane state: current king hash and
   the pinned benchmark snapshot fingerprint.
7. Decision: merge, close-losing, close-invalid, or rerun-stale.
8. Winners are merged, labeled for GitTensor, published as the new king, and
   recorded in `promotion_record.json`.
