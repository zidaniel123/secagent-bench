"""Token pricing, in USD per million tokens.

Only the Anthropic rates are hard-coded, because they are the ones this project
can state with confidence. Every other provider is left as ``None`` on purpose:
a made-up price is worse than a blank column, because it silently corrupts the
cost comparison that is half the point of this benchmark.

Fill the rest in ``configs/pricing.yaml`` from the provider's own pricing page —
the loader merges that file over these defaults. Until you do, cost shows "—"
for those models and every other metric still works.

Local models are billed at zero. That is not a claim that self-hosting is free;
it means the marginal cost of a request is not an API charge. Amortised hardware
and power are real and this harness does not model them.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

#: (input $/1M, output $/1M)
Price = tuple[float, float]

_ANTHROPIC: dict[str, Price] = {
    "claude-opus-5": (5.00, 25.00),
    "claude-opus-4-8": (5.00, 25.00),
    "claude-sonnet-5": (2.00, 10.00),
    "claude-haiku-4-5": (1.00, 5.00),
    "claude-fable-5-1": (10.00, 50.00),
}

#: Models we deliberately refuse to guess at. Override in configs/pricing.yaml.
_UNPRICED: dict[str, None] = {
    "gpt-5": None,
    "kimi-k3": None,
    "glm-4.6": None,
}

DEFAULT_PRICING: dict[str, Price | None] = {**_ANTHROPIC, **_UNPRICED}


def load_pricing(path: str | Path | None = None) -> dict[str, Price | None]:
    """Merge a user pricing file over the built-in defaults."""
    pricing: dict[str, Price | None] = dict(DEFAULT_PRICING)
    if path is None:
        return pricing
    p = Path(path)
    if not p.exists():
        return pricing

    import yaml

    data: dict[str, Any] = yaml.safe_load(p.read_text()) or {}
    for model, entry in data.items():
        if entry is None:
            pricing[model] = None
        elif isinstance(entry, dict):
            pricing[model] = (float(entry["input"]), float(entry["output"]))
        elif isinstance(entry, (list, tuple)) and len(entry) == 2:
            pricing[model] = (float(entry[0]), float(entry[1]))
    return pricing


def cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    pricing: dict[str, Price | None] | None = None,
    metered: bool = True,
) -> float | None:
    """Cost of one call, or ``None`` when the model's price is unknown.

    ``None`` propagates: an unpriced model reports no cost rather than $0.00,
    which would otherwise make it look free next to a priced one.
    """
    if not metered:
        return 0.0
    table = pricing if pricing is not None else DEFAULT_PRICING
    price = table.get(model)
    if price is None:
        return None
    in_rate, out_rate = price
    return (input_tokens / 1_000_000) * in_rate + (output_tokens / 1_000_000) * out_rate
