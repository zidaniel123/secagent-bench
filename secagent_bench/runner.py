"""The benchmark loop: providers × tasks × cases × repeats."""

from __future__ import annotations

import concurrent.futures as cf
import datetime as dt
import platform
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import providers as prov
from . import tasks as task_registry
from .tasks.base import Case, Task


@dataclass
class ProviderSpec:
    """One column in the comparison table."""

    id: str
    model: str | None = None
    options: dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.id}:{self.model}" if self.model else self.id


@dataclass
class SuiteConfig:
    providers: list[ProviderSpec]
    tasks: list[str]
    repeats: int = 1
    max_tokens: int = 2048
    workers: int = 4
    fixtures: Path = Path("fixtures")
    pricing_file: Path | None = None


def run_suite(
    config: SuiteConfig,
    on_event: Callable[[str], None] | None = None,
) -> dict[str, Any]:
    """Execute the suite and return a results document."""
    log = on_event or (lambda _msg: None)
    pricing = prov.load_pricing(config.pricing_file)

    runs: list[dict[str, Any]] = []
    summary: dict[str, dict[str, Any]] = {}

    for spec in config.providers:
        log(f"provider {spec.key}")
        try:
            provider = prov.build(spec.id, spec.model, **spec.options)
        except Exception as exc:  # noqa: BLE001
            # A provider that cannot even be constructed (missing key, bad
            # preset) is recorded and skipped — the rest of the suite still runs.
            log(f"  ! {type(exc).__name__}: {exc}")
            summary[spec.key] = {"unavailable": f"{type(exc).__name__}: {exc}"}
            continue

        metered = prov.is_metered(provider)
        summary[spec.key] = {}

        for task_name in config.tasks:
            task = task_registry.build(task_name)
            cases = task.load(config.fixtures)
            log(f"  {task_name}: {len(cases)} cases × {config.repeats}")

            outcomes = _run_task(
                provider=provider,
                task=task,
                cases=cases,
                config=config,
                pricing=pricing,
                metered=metered,
                provider_key=spec.key,
            )
            runs.extend(outcomes)
            summary[spec.key][task_name] = task.aggregate(outcomes)

    return {
        "meta": {
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "host": platform.node(),
            "repeats": config.repeats,
            "tasks": config.tasks,
            "providers": [s.key for s in config.providers],
        },
        "summary": summary,
        "runs": runs,
    }


def _run_task(
    provider: prov.Provider,
    task: Task,
    cases: list[Case],
    config: SuiteConfig,
    pricing: dict[str, Any],
    metered: bool,
    provider_key: str,
) -> list[dict[str, Any]]:
    jobs = [(case, rep) for case in cases for rep in range(config.repeats)]

    def one(job: tuple[Case, int]) -> dict[str, Any]:
        case, rep = job
        result = provider.complete(
            task.system_prompt(),
            task.user_prompt(case),
            max_tokens=config.max_tokens,
        )
        outcome = task.evaluate(case, result)
        outcome.update(
            {
                "provider": provider_key,
                "task": task.name,
                "repeat": rep,
                "latency_s": round(result.latency_s, 3),
                "input_tokens": result.input_tokens,
                "output_tokens": result.output_tokens,
                "cost_usd": prov.cost_usd(
                    provider.model,
                    result.input_tokens,
                    result.output_tokens,
                    pricing,
                    metered=metered,
                ),
            }
        )
        return outcome

    if config.workers <= 1:
        return [one(job) for job in jobs]

    with cf.ThreadPoolExecutor(max_workers=config.workers) as pool:
        return list(pool.map(one, jobs))
