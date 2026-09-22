"""Provider abstraction.

Every backend — hosted API or a local model on your own GPU — is reduced to one
call: `complete(system, user)` -> `ChatResult`. That is what makes the providers
comparable; the benchmark never knows which one it is talking to.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class ChatResult:
    """One completion, plus everything the benchmark needs to score it."""

    text: str
    provider: str
    model: str

    input_tokens: int = 0
    output_tokens: int = 0
    latency_s: float = 0.0

    #: True when the provider *structurally* declined (e.g. Anthropic's
    #: ``stop_reason == "refusal"``). Heuristic refusals are flagged separately
    #: by :func:`secagent_bench.scoring.looks_like_refusal`.
    hard_refusal: bool = False
    refusal_category: str | None = None

    #: Populated when the call failed outright. A run with `error` set is
    #: recorded, not silently dropped — a provider that errors on half the
    #: suite must not look like a provider that scored zero on half the suite.
    error: str | None = None

    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.error is None


class Provider(ABC):
    """Base class for every backend."""

    #: Short id used in configs and report columns, e.g. ``"anthropic"``.
    name: str = "base"

    def __init__(self, model: str, **options: Any) -> None:
        self.model = model
        self.options = options

    @abstractmethod
    def _complete(self, system: str, user: str, max_tokens: int) -> ChatResult:
        """Do the actual API call. Subclasses implement this."""

    def complete(self, system: str, user: str, max_tokens: int = 4096) -> ChatResult:
        """Timed, error-trapping wrapper around :meth:`_complete`."""
        start = time.perf_counter()
        try:
            result = self._complete(system, user, max_tokens)
        except Exception as exc:  # noqa: BLE001 - a failing provider is data, not a crash
            return ChatResult(
                text="",
                provider=self.name,
                model=self.model,
                latency_s=time.perf_counter() - start,
                error=f"{type(exc).__name__}: {exc}",
            )
        if not result.latency_s:
            result.latency_s = time.perf_counter() - start
        return result

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} {self.name}:{self.model}>"
