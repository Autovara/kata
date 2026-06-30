from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class SourceFact:
    value: str
    source: str


@dataclass
class PromptData:
    title: str
    repo_display_name: str
    github_full_name: str | None
    summary: SourceFact | None = None
    rules: list[SourceFact] = field(default_factory=list)
    commands: list[SourceFact] = field(default_factory=list)
    protected_paths: list[SourceFact] = field(default_factory=list)
    registry_notes: list[SourceFact] = field(default_factory=list)
    unknowns: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
