"""The subnet plugin contract (Phase 1 of the multi-subnet refactor).

A subnet plugin bundles everything subnet-specific -- task, environment, scorer, and
config -- behind one interface so the Kata core can run its King-of-the-Hill
competition without knowing what any subnet does. SN60 is just the first plugin.

Nothing calls this yet: SN60 is wrapped against it in Phase 2, and the core round /
decision paths are routed through it in Phases 3-4.
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


class ScoringProfile(str, Enum):
    """How the core must treat a subnet's scores."""

    # Objective and offline: the king's score is reproducible, so it can be cached
    # by benchmark identity and re-used across a round (e.g. SN60).
    DETERMINISTIC = "deterministic"
    # Live and/or LLM-judged: scores drift run-to-run, so the core averages repeats
    # and re-scores the king every round (e.g. SN22).
    NOISY = "noisy"


@dataclass(frozen=True)
class EnvSpec:
    """The environment a candidate agent must run in."""

    # "none": fully sealed. "relay_only": only the pinned-model relay (SN60).
    # "allowlist": relay + the hosts in ``allowed_hosts`` (live subnets like SN22).
    network: NetworkPolicy = "relay_only"
    allowed_hosts: tuple[str, ...] = ()
    # Secret env vars the validator injects into the sandbox; never agent-readable
    # output, only inputs the task needs (e.g. a data-provider API key).
    required_secrets: tuple[str, ...] = ()
    # Per-subnet relay model; None means the platform default.
    pinned_model: str | None = None
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

    #: Stable evaluator id; equals the lane's ``evaluator_id`` (e.g. "sn60_bitsec").
    evaluator_id: str
    #: Submission pack segment -- submissions/<pack>/<mode>/<id>/ (e.g. "sn60__bitsec").
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
        """Produce this round's task set (deterministic in ``seed`` where possible)."""

    @abstractmethod
    def benchmark_identity(self, problems: ProblemSet) -> str:
        """A hash identifying the benchmark for king caching / freshness.

        An empty string means "not cacheable" -- the core re-scores the king every
        round instead of reusing a cached score (required for noisy/live subnets).
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

    def run_round(
        self,
        *,
        king_agent_path: str,
        candidates: list[tuple[str, str]],
        config: dict[str, Any],
        output_root: str,
        run_id: str | None = None,
        score_king: bool = True,
        progress_path: str | None = None,
    ) -> object:
        """Run one competition round for this subnet and return its result.

        The default drives the generic orchestrator and returns a ``RoundOutcome``;
        subnets that produce their own proof/summary files (e.g. SN60) override this
        to write them and return their native result. Imported lazily to avoid a
        module-load cycle with ``kata.core.round``.
        """
        from kata.core.round import run_plugin_round

        return run_plugin_round(
            self,
            king_agent_path=king_agent_path,
            candidates=candidates,
            config=config,
            output_root=output_root,
            seed=run_id or "round",
            score_king=score_king,
        )
