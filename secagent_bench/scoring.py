"""Parsing and metrics.

Kept deliberately free of model calls so it is unit-testable and deterministic:
the model decides what it found, this module decides what that counts as.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

# --------------------------------------------------------------------------
# Response parsing
# --------------------------------------------------------------------------

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> dict | list | None:
    """Pull the first JSON object/array out of a model response.

    Models wrap JSON in prose or code fences even when told not to. Failing to
    parse is scored as a malformed response, not as "no findings" — those are
    different failures and collapsing them flatters models that ramble.
    """
    if not text or not text.strip():
        return None

    candidates: list[str] = []
    for match in _FENCE.finditer(text):
        candidates.append(match.group(1).strip())
    candidates.append(text.strip())

    for candidate in candidates:
        try:
            return json.loads(candidate)
        except json.JSONDecodeError:
            pass
        # Fall back to the outermost {...} or [...] span.
        for opener, closer in (("{", "}"), ("[", "]")):
            start, end = candidate.find(opener), candidate.rfind(closer)
            if start != -1 and end > start:
                try:
                    return json.loads(candidate[start : end + 1])
                except json.JSONDecodeError:
                    continue
    return None


_CWE = re.compile(r"CWE[-_\s]?(\d{1,4})", re.IGNORECASE)


def normalize_cwe(value: object) -> str | None:
    """``'cwe 89'`` / ``89`` / ``'CWE-89'`` -> ``'CWE-89'``."""
    if value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}"
    match = _CWE.search(str(value))
    return f"CWE-{int(match.group(1))}" if match else None


def findings_cwes(payload: object) -> set[str]:
    """Every CWE mentioned in a parsed findings payload."""
    out: set[str] = set()
    if isinstance(payload, dict):
        items = payload.get("findings", payload.get("results", []))
    elif isinstance(payload, list):
        items = payload
    else:
        return out
    if not isinstance(items, list):
        return out
    for item in items:
        if isinstance(item, dict):
            cwe = normalize_cwe(item.get("cwe") or item.get("cwe_id") or item.get("id"))
        else:
            cwe = normalize_cwe(item)
        if cwe:
            out.add(cwe)
    return out


# --------------------------------------------------------------------------
# Refusal detection
# --------------------------------------------------------------------------

_REFUSAL_PATTERNS = [
    r"\bi (?:can'?t|cannot|won'?t|am unable to)\b.{0,60}"
    r"\b(?:help|assist|analy[sz]e|provide|do that)\b",
    r"\bi'?m (?:sorry|afraid)\b.{0,40}\b(?:can'?t|cannot|unable)\b",
    r"\bas an ai\b.{0,60}\b(?:cannot|can'?t|not able)\b",
    r"\bi (?:must|have to) (?:decline|refuse)\b",
    r"\bthis (?:request|content) (?:violates|goes against)\b",
    r"\bi don'?t (?:feel comfortable|think it'?s appropriate)\b",
]
_REFUSAL_RE = [re.compile(p, re.IGNORECASE) for p in _REFUSAL_PATTERNS]


def looks_like_refusal(text: str) -> bool:
    """Heuristic refusal detection for providers with no structured signal.

    Only consulted when the provider did not report a refusal itself (Anthropic
    does, via ``stop_reason``). Scoped to the opening of the response so a
    finding that merely *quotes* refusal-shaped text is not miscounted.
    """
    if not text or not text.strip():
        return False
    head = text.strip()[:400]
    return any(rx.search(head) for rx in _REFUSAL_RE)


# --------------------------------------------------------------------------
# Metrics
# --------------------------------------------------------------------------


@dataclass
class Counts:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return self.tp / denom if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return self.tp / denom if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def accuracy(self) -> float:
        total = self.tp + self.fp + self.fn + self.tn
        return (self.tp + self.tn) / total if total else 0.0

    def as_dict(self) -> dict[str, float | int]:
        return {
            "tp": self.tp,
            "fp": self.fp,
            "fn": self.fn,
            "tn": self.tn,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "accuracy": round(self.accuracy, 4),
        }


def mean(values: list[float]) -> float:
    return sum(values) / len(values) if values else 0.0


def pct(part: int, whole: int) -> float:
    return (part / whole * 100.0) if whole else 0.0
