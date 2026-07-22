"""The subnet plugin contract.

A subnet plugin bundles everything subnet-specific -- task, environment, scorer, screening,
and config -- behind one interface so the Kata core runs its King-of-the-Hill competition
without knowing what any subnet does. The core resolves a plugin by evaluator id and calls
only the members below; adding a subnet is a new plugin, not a core change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal

# Opaque handles: only the owning plugin understands these. The core receives one
# from a plugin method and passes it back to the same plugin's later methods without
# inspecting it. Typed as Any so the core stays subnet-agnostic.
ProblemSet = Any
RawRun = Any

NetworkPolicy = Literal["none", "relay_only", "allowlist"]
# Where a candidate runs: "sandbox" (local, validator-run) or "tee" (a remote sealed room the miner
# pays for, e.g. the Phala confidential VM). The platform reads this to pick the execution backend
# generically, so a subnet opts into miner-paid TEE execution by declaring it here.
ExecutionBackend = Literal["sandbox", "tee"]


class ScoringProfile(str, Enum):
    """The evaluator's score reproducibility characteristic."""

    # Objective and offline: an evaluator may safely cache scores using its benchmark
    # identity and artifact hash.
    DETERMINISTIC = "deterministic"
    # Live and/or LLM-judged: scores drift run-to-run, so the evaluator should score
    # each contender afresh according to its own policy.
    NOISY = "noisy"


@dataclass(frozen=True)
class EnvSpec:
    """The environment a candidate agent must run in."""

    # "none": fully sealed. "relay_only": only the subnet's execution gateway.
    # "allowlist": execution gateway plus the hosts in ``allowed_hosts``.
    network: NetworkPolicy = "relay_only"
    allowed_hosts: tuple[str, ...] = ()
    # Secret env vars the validator injects into the sandbox; never agent-readable
    # output, only inputs the task needs (e.g. a data-provider API key).
    required_secrets: tuple[str, ...] = ()
    # Execution backend the lane runs candidates in (see ExecutionBackend). Default: local sandbox.
    execution: ExecutionBackend = "sandbox"
    resources: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ScoreCard:
    """A candidate's normalized result -- the only score object the core inspects."""

    # Single number the core ranks by; higher is better.
    comparable: float
    # Was this a valid run at all? A failed run must never rank above a valid one.
    passed: bool
    # Margin a challenger must exceed the king by to win (0.0 == strict greater-than).
    beats_threshold: float = 0.0
    # Free-form display metrics (precision, f1, relevance, ...) for proofs/dashboard.
    # Must stay JSON-serializable; native/opaque objects go in ``payload`` instead.
    metrics: dict[str, Any] = field(default_factory=dict)
    # Opaque plugin-native result (e.g. the subnet's own summary object). The core
    # never inspects or serializes this; the plugin uses it in compare()/beats_king().
    payload: Any = None


@dataclass(frozen=True)
class ProgressUpdate:
    """A subnet-agnostic progress tick the core can render live."""

    variant: str  # "king" or a candidate/submission id
    done: int
    total: int
    state: str  # "queued" | "scoring" | "done" | "failed"
    metrics: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RunContext:
    """What the core provides to a plugin run.

    Subnet-specific test seams (e.g. execution hooks) travel via the plugin's own
    config/constructor, not here, so the core stays generic.
    """

    output_root: str
    env: EnvSpec
    # Identifies the variant being run (e.g. "king" or a submission id) so the plugin
    # can lay out per-variant artifacts without collision.
    label: str = "candidate"
    progress: Callable[[ProgressUpdate], None] | None = None


class SubnetPlugin(ABC):
    """The contract every subnet implements to compete on Kata.

    A plugin is *task + environment + scorer + config*, fully self-contained. The core
    calls only these members and never imports subnet-specific code. Concrete plugins
    set the class attributes below and implement the abstract methods.
    """

    #: Stable evaluator id; equals the lane's ``evaluator_id``.
    evaluator_id: str
    #: Submission pack segment -- submissions/<pack>/<mode>/<id>/.
    pack: str
    #: Submission mode segment (e.g. "miner").
    mode: str
    #: How the core treats scores (cacheable king vs run-averaged).
    scoring_profile: ScoringProfile
    #: Identity recorded in summaries for freshness checks (e.g. the validator model).
    validator_identity: str

    @abstractmethod
    def environment_spec(self) -> EnvSpec:
        """The sandbox/network/secret requirements for running a candidate."""

    @abstractmethod
    def sample_problems(self, *, seed: str, config: dict[str, Any]) -> ProblemSet:
        """Produce this challenge's task set (deterministic in ``seed`` where possible)."""

    @abstractmethod
    def benchmark_identity(self, problems: ProblemSet) -> str:
        """A hash identifying the benchmark for evaluator caching and freshness.

        An empty string means the evaluator must not treat the benchmark as cacheable.
        """

    @abstractmethod
    def run_candidate(
        self, *, agent_path: str, problems: ProblemSet, context: RunContext
    ) -> RawRun:
        """Execute one candidate agent on the problem set in the subnet's environment."""

    @abstractmethod
    def score(self, raw: RawRun, problems: ProblemSet) -> ScoreCard:
        """Run the subnet's validation over a raw run and normalize it to a ScoreCard."""

    @abstractmethod
    def compare(self, a: ScoreCard, b: ScoreCard) -> int:
        """Order two score cards: negative if a < b, positive if a > b, 0 if equal."""

    @abstractmethod
    def beats_king(self, candidate: ScoreCard, king: ScoreCard | None) -> bool:
        """Whether a challenger strictly beats the reigning king (None == no king yet)."""

    def static_screen(self, submission_path: str) -> object | None:
        """Optional subnet-specific static checks before running. Default: no extra checks."""
        return None

    def record_promotion_provenance(
        self, *, entry, verification, summary, public_root: str | None = None
    ) -> None:
        """Persist any subnet-specific promotion/provenance records for a promoted winner.

        The generic promotion path calls this after a challenger wins; the plugin writes
        whatever lane provenance it needs (challenge state, benchmark snapshot, …).
        Default: nothing.
        """
        return None

    def hash_bundle(self, path) -> str:
        """Hash a king/candidate bundle for king-currency checks.

        Must match how the subnet hashes bundles during a challenge so a published king stays
        recognized as current. Default: the generic submission-bundle hash.
        """
        from pathlib import Path

        from kata.screening.rules import hash_submission_bundle

        return hash_submission_bundle(Path(path))

    def benchmark_is_current(self, *, lane_id, summary, public_root=None) -> bool:
        """Whether a challenge summary's benchmark identity still matches the lane's.

        Used by the generic verifier's staleness check. Default: always current.
        """
        return True

    def extra_verification_reasons(self, *, lane_id, summary, public_root=None) -> list[str]:
        """Extra subnet-specific reject reasons during verification. Default: none."""
        return []

    def load_challenge_summary(self, path):
        """Load this subnet's challenge/challenge summary from ``path``.

        The summary is the subnet's native challenge result; the generic verify/promote path
        reads only common attributes off it. The default handles the common summary emitted
        by the ScoreCard-only challenge runner; a plugin with a richer native format can
        override it.
        """
        from kata.core.challenge import load_generic_challenge_summary

        return load_generic_challenge_summary(path)

    def benchmark_review(self, bundle_files, *, strict):
        """Subnet anti-memorization review of a candidate bundle.

        Returns ``(reject_findings, review_findings, score)``. In ``strict`` mode the
        subnet may promote concrete evidence from review to reject. Default: nothing.
        """
        return [], [], 0.0

    def register_cli(self, subparsers) -> None:
        """Contribute this subnet's own top-level ``kata`` subcommands. Default: none."""

    def llm_review(self, *, submission_root, bundle_files, decision):
        """Optional subnet LLM review of a suspicious submission.

        Returns ``(findings, notes)``. Default: none.
        """
        return [], []

    def add_challenge_arguments(self, parser) -> None:
        """Register this subnet's ``kata challenge`` CLI arguments. Default: none."""

    def build_challenge_config(self, args) -> dict:
        """Build the challenge config dict from parsed CLI args. Default: empty."""
        return {}

    def challenge_result_json(self, result) -> dict:
        """Serialize the default ScoreCard challenge result for CLI consumers.

        The payload contains one ordered ``rank_signals`` list per variant.  Its
        single default signal, ``comparable``, is derived directly from ScoreCard,
        so a plugin need not reimplement a JSON adapter merely to work with a
        continuous multi-lane kata-bot.
        """
        from kata.core.challenge import generic_challenge_result_json

        return generic_challenge_result_json(self, result)

    def render_challenge_text(self, result) -> str:
        """Render a challenge result as human-readable text. Default: repr."""
        return str(result)

    def run_challenge(
        self,
        *,
        king_agent_path: str,
        candidates: list[tuple[str, str]],
        config: dict[str, Any],
        output_root: str,
        run_id: str | None = None,
        progress_path: str | None = None,
    ) -> object:
        """Run one competition challenge for this subnet and return its result.

        The default drives the generic orchestrator, persists common ScoreCard
        challenge summaries, and returns a ``GenericChallengeResult``. Subnets
        that produce their own proof/summary files can override it. Imported lazily
        to avoid a module-load cycle with ``kata.core.challenge``.
        """
        from kata.core.challenge import run_generic_plugin_challenge

        return run_generic_plugin_challenge(
            self,
            king_agent_path=king_agent_path,
            candidates=candidates,
            config=config,
            output_root=output_root,
            run_id=run_id,
        )
