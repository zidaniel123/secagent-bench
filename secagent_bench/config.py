"""Suite config loading."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .runner import ProviderSpec, SuiteConfig

RESERVED = {"id", "provider", "model"}


def load_suite(path: str | Path) -> SuiteConfig:
    import yaml

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Suite config not found: {p}")
    data: dict[str, Any] = yaml.safe_load(p.read_text()) or {}

    specs: list[ProviderSpec] = []
    for entry in data.get("providers", []):
        if isinstance(entry, str):
            specs.append(ProviderSpec(id=entry))
            continue
        pid = entry.get("id") or entry.get("provider")
        if not pid:
            raise ValueError(f"Provider entry is missing `id`: {entry!r}")
        # Anything that is not a reserved key is passed to the provider
        # constructor — base_url, api_key, effort, temperature, and so on.
        options = {k: v for k, v in entry.items() if k not in RESERVED}
        specs.append(ProviderSpec(id=pid, model=entry.get("model"), options=options))

    if not specs:
        raise ValueError(
            f"{p} lists no providers. Add at least one under `providers:`."
        )

    pricing = data.get("pricing")
    return SuiteConfig(
        providers=specs,
        tasks=list(data.get("tasks", ["sast", "injection"])),
        repeats=int(data.get("repeats", 1)),
        max_tokens=int(data.get("max_tokens", 2048)),
        workers=int(data.get("workers", 4)),
        fixtures=Path(data.get("fixtures", "fixtures")),
        pricing_file=Path(pricing) if pricing else None,
    )
