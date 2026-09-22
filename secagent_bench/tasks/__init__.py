"""Task registry."""

from __future__ import annotations

from .base import Case, Task
from .dast import DastInjectionTask, DastTask
from .injection import InjectionTask
from .sast import SastTask

REGISTRY: dict[str, type[Task]] = {
    SastTask.name: SastTask,
    DastTask.name: DastTask,
    InjectionTask.name: InjectionTask,
    DastInjectionTask.name: DastInjectionTask,
}


def build(name: str) -> Task:
    if name not in REGISTRY:
        raise ValueError(
            f"Unknown task {name!r}. Known: {', '.join(sorted(REGISTRY))}"
        )
    return REGISTRY[name]()


__all__ = ["REGISTRY", "Case", "Task", "build"]
