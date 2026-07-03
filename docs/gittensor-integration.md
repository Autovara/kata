# GitTensor Integration

Kata should integrate with GitTensor as a trusted-label repository.

GitTensor scores merged pull requests. Kata scores challenger agents. The
adapter between those systems is:

1. Kata evaluates a challenger against the current king.
2. `kata-bot` closes invalid, losing, and stale PRs.
3. `kata-bot` merges only confirmed promotion winners.
4. Before merging a winner, `kata-bot` applies trusted labels:
   - `kata:winner:<subnet-pack>`
   - `kata:mode:<mode>`
5. GitTensor rewards only merged PRs with a trusted subnet-pack winner label.

This means GitTensor rewards promotion events, not raw PR size. Time decay in
GitTensor then approximates current-king rewards: newer king promotions retain
more score than older promotions, and miners who win multiple times accumulate
multiple scored promotion events.

## Recommended Registry Entry

Use this shape in GitTensor's `master_repositories.json`, replacing
`YOUR_ORG/kata` and choosing an emission share that fits the live registry:

```json
"YOUR_ORG/kata": {
  "emission_share": 0.025,
  "issue_discovery_share": 0.0,
  "maintainer_cut": 0.0,
  "additional_acceptable_branches": ["main"],
  "trusted_label_pipeline": true,
  "default_label_multiplier": 0.0,
  "fixed_base_score": 1.0,
  "label_multipliers": {
    "kata:winner:*": 1.0,
    "kata:invalid": 0.0,
    "kata:losing": 0.0,
    "kata:stale": 0.0,
    "kata:hold": 0.0
  },
  "eligibility": {
    "min_valid_merged_prs": 1,
    "min_credibility": 0.0,
    "max_open_pr_threshold": 10
  },
  "scoring": {
    "pr_lookback_days": 14,
    "open_pr_collateral_percent": 0.0,
    "time_decay": {
      "grace_period_hours": 0,
      "sigmoid_midpoint_days": 3,
      "sigmoid_steepness": 1.25,
      "min_multiplier": 0.01
    }
  }
}
```

For lane-weighted rewards, replace the generic wildcard multiplier with
specific subnet-pack multipliers:

```json
"label_multipliers": {
  "kata:winner:sn60__bitsec": 1.0,
  "kata:winner:*": 0.5
}
```

GitTensor resolves the highest matching label multiplier, so specific
subnet-pack labels can override the fallback wildcard.

## Operational Rules

- Only `kata-bot` or maintainers should apply `kata:winner:*` labels.
- Losing or invalid PRs must not merge.
- Kata does not use GitTensor issue discovery. Keep `issue_discovery_share` at
  `0.0`; this field is the GitTensor switch that disables the issue pool for
  the repo.
- A winning PR must be labeled before merge; otherwise GitTensor may not score
  it as a Kata promotion.
- Keep `default_label_multiplier` at `0.0` so normal maintenance PRs do not
  receive emissions.
- Keep `fixed_base_score` enabled so PR size does not dominate rewards.
- Keep a short lookback and strong time decay if the desired behavior is
  "recent kings earn more than old kings."
