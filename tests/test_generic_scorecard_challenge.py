"""The default plugin path must expose ScoreCard results to continuous lanes."""

from __future__ import annotations

from pathlib import Path

from kata.plugins.contract import EnvSpec, ScoreCard, ScoringProfile, SubnetPlugin


class _ScoreCardPlugin(SubnetPlugin):
    evaluator_id = "scorecard-test"
    pack = "scorecard__test"
    mode = "miner"
    scoring_profile = ScoringProfile.DETERMINISTIC
    validator_identity = "scorecard-test-v1"

    def environment_spec(self) -> EnvSpec:
        return EnvSpec()

    def sample_problems(self, *, seed: str, config: dict) -> dict[str, str]:
        return {"seed": seed}

    def benchmark_identity(self, problems: dict[str, str]) -> str:
        return "scorecard-benchmark"

    def run_candidate(self, *, agent_path: str, problems: dict, context) -> float:
        return float(Path(agent_path).name)

    def score(self, raw: float, problems: dict) -> ScoreCard:
        return ScoreCard(comparable=raw, passed=True, beats_threshold=0.1)

    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        return (a.comparable > b.comparable) - (a.comparable < b.comparable)

    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        return king is None or candidate.comparable - king.comparable > candidate.beats_threshold

    def hash_bundle(self, path: Path) -> str:
        return f"hash:{path.name}"


def test_default_scorecard_json_and_summary_are_promotion_ready(tmp_path: Path) -> None:
    plugin = _ScoreCardPlugin()
    king = tmp_path / "0.4"
    candidate = tmp_path / "0.8"
    king.mkdir()
    candidate.mkdir()

    result = plugin.run_challenge(
        king_agent_path=str(king),
        candidates=[("pr-9", str(candidate))],
        config={},
        output_root=str(tmp_path / "runs"),
        run_id="scorecard-run",
    )
    payload = plugin.challenge_result_json(result)

    assert payload["king"]["artifact_hash"] == "hash:0.4"
    entry = payload["entries"][0]
    assert entry["rank_signals"] == [
        {
            "name": "comparable",
            "value": 0.8,
            "higher_better": True,
            "beats_threshold": 0.1,
        }
    ]
    summary = plugin.load_challenge_summary(entry["challenge_summary_path"])
    assert summary.candidate_artifact_hash == "hash:0.8"
    assert summary.king_artifact_hash == "hash:0.4"
    assert summary.promotion_ready is True
