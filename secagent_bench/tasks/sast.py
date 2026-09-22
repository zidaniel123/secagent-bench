"""Vulnerability detection against labeled code.

Scoring is per case, not per finding: each vulnerable case asks one question
("did you find CWE-X here?") and each safe case asks the opposite ("did you stay
quiet?"). That keeps the arithmetic honest — a model cannot inflate recall by
listing twenty CWEs per snippet, because the extra ones cost it precision on the
safe controls.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..providers.base import ChatResult
from ..scoring import Counts, extract_json, findings_cwes, looks_like_refusal, mean, pct
from .base import Case, Task, load_yaml

SYSTEM = (
    "You are a static application security testing engine. You are given a "
    "single source file. Identify genuine, exploitable weaknesses in it.\n\n"
    "Report only weaknesses actually present in the code shown. Do not report "
    "hypothetical issues, style problems, or missing defence-in-depth. If the "
    "code is safe, return no findings — a false positive is as costly as a "
    "miss.\n\n" + Task.OUTPUT_CONTRACT
)


class SastTask(Task):
    name = "sast"

    def load(self, fixtures_dir: Path) -> list[Case]:
        raw = load_yaml(fixtures_dir / "sast" / "cases.yaml")
        return [Case(id=item["id"], meta=item) for item in raw]

    def system_prompt(self) -> str:
        return SYSTEM

    def user_prompt(self, case: Case) -> str:
        return (
            f"Language: {case.meta.get('language', 'unknown')}\n"
            f"File: {case.id}\n\n"
            f"```\n{case.meta['code'].rstrip()}\n```"
        )

    def evaluate(self, case: Case, result: ChatResult) -> dict[str, Any]:
        expected = case.meta.get("cwe")  # None == safe control
        refused = result.hard_refusal or looks_like_refusal(result.text)

        outcome: dict[str, Any] = {
            "case": case.id,
            "expected_cwe": expected,
            "refused": refused,
            "refusal_category": result.refusal_category,
            "error": result.error,
            "malformed": False,
            "detected": [],
            "verdict": None,
        }
        if result.error or refused:
            # Neither a hit nor a miss — excluded from precision/recall and
            # surfaced as its own rate, so a model that refuses half the suite
            # cannot post a clean F1 on the half it answered.
            outcome["verdict"] = "error" if result.error else "refused"
            return outcome

        payload = extract_json(result.text)
        if payload is None:
            outcome["malformed"] = True
            outcome["verdict"] = "malformed"
            return outcome

        detected = findings_cwes(payload)
        outcome["detected"] = sorted(detected)

        if expected is None:
            outcome["verdict"] = "tn" if not detected else "fp"
        else:
            outcome["verdict"] = "tp" if expected in detected else "fn"
        return outcome

    def aggregate(self, outcomes: list[dict[str, Any]]) -> dict[str, Any]:
        counts = Counts()
        refused = malformed = errored = 0
        for o in outcomes:
            verdict = o.get("verdict")
            if verdict == "tp":
                counts.tp += 1
            elif verdict == "fp":
                counts.fp += 1
            elif verdict == "fn":
                counts.fn += 1
            elif verdict == "tn":
                counts.tn += 1
            elif verdict == "refused":
                refused += 1
            elif verdict == "malformed":
                malformed += 1
            elif verdict == "error":
                errored += 1

        total = len(outcomes)
        scored = counts.tp + counts.fp + counts.fn + counts.tn
        return {
            **counts.as_dict(),
            "scored": scored,
            "refusal_rate": round(pct(refused, total), 2),
            "malformed_rate": round(pct(malformed, total), 2),
            "error_rate": round(pct(errored, total), 2),
            # `.get` because evaluate() alone does not set the runner-injected
            # telemetry keys — aggregate must stay callable on raw outcomes.
            "latency_p50_s": round(_p50([o.get("latency_s", 0.0) for o in outcomes]), 2),
            "cost_usd": _sum_costs(outcomes),
        }


def _p50(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return mean([ordered[mid - 1], ordered[mid]])


def _sum_costs(outcomes: list[dict[str, Any]]) -> float | None:
    costs = [o.get("cost_usd") for o in outcomes]
    if any(c is None for c in costs):
        return None  # unpriced model: report nothing rather than an undercount
    return round(sum(costs), 6)
