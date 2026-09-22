"""Task interface.

A task owns three things: the cases, the prompt, and what counts as correct.
The runner owns none of them — it just walks providers × cases × repeats.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..providers.base import ChatResult


@dataclass
class Case:
    id: str
    meta: dict[str, Any] = field(default_factory=dict)


class Task(ABC):
    name: str = "base"

    #: Every task asks for the same JSON shape so one parser serves all of them
    #: and a model is never penalised for guessing a different schema per task.
    OUTPUT_CONTRACT = (
        'Respond with JSON only, no prose and no code fence:\n'
        '{"findings": [{"cwe": "CWE-79", "severity": "high", '
        '"rationale": "one sentence"}]}\n'
        'Use an empty findings array if the code is safe. '
        'Use the CWE id that best matches the weakness.'
    )

    @abstractmethod
    def load(self, fixtures_dir: Path) -> list[Case]:
        """Read this task's cases off disk."""

    @abstractmethod
    def system_prompt(self) -> str:
        ...

    @abstractmethod
    def user_prompt(self, case: Case) -> str:
        ...

    @abstractmethod
    def evaluate(self, case: Case, result: ChatResult) -> dict[str, Any]:
        """Score one response. Returns a flat dict merged into the run record."""

    @abstractmethod
    def aggregate(self, outcomes: list[dict[str, Any]]) -> dict[str, Any]:
        """Roll per-case outcomes up into one provider's summary row."""


def load_yaml(path: Path) -> Any:
    import yaml

    if not path.exists():
        raise FileNotFoundError(
            f"Fixture file not found: {path}. Run from the repo root, or pass "
            "--fixtures to point at the fixtures/ directory."
        )
    return yaml.safe_load(path.read_text())
