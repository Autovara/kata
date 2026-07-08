from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

ScreeningSeverity = Literal["reject", "review", "note"]
ScreeningStatus = Literal["pass", "reject", "review"]


@dataclass(frozen=True)
class ScreeningFinding:
    rule_id: str
    severity: ScreeningSeverity
    path: str | None
    line: int | None
    reason: str
    evidence: str


@dataclass(frozen=True)
class ScreeningDecision:
    status: ScreeningStatus
    reject_reasons: list[ScreeningFinding] = field(default_factory=list)
    review_reasons: list[ScreeningFinding] = field(default_factory=list)
    notes: list[ScreeningFinding] = field(default_factory=list)
    score: int = 0

    @property
    def passed(self) -> bool:
        return self.status == "pass"

    def rejection_messages(self) -> list[str]:
        return [finding.reason for finding in self.reject_reasons]
