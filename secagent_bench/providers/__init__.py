"""Provider registry.

``build("anthropic", model=...)`` is the only entry point the rest of the
benchmark uses, so adding a backend means adding one line here.
"""

from __future__ import annotations

from typing import Any

from .base import ChatResult, Provider
from .openai_compat import PRESETS, OpenAICompatProvider
from .pricing import cost_usd, load_pricing

#: Every id accepted in a suite config's `provider:` field.
KNOWN = ("anthropic", *PRESETS.keys())


def build(provider: str, model: str | None = None, **options: Any) -> Provider:
    """Construct a provider by id."""
    if provider == "anthropic":
        from .anthropic_provider import DEFAULT_MODEL, AnthropicProvider

        return AnthropicProvider(model or DEFAULT_MODEL, **options)
    if provider in PRESETS:
        return OpenAICompatProvider(preset=provider, model=model, **options)
    raise ValueError(
        f"Unknown provider {provider!r}. Known: {', '.join(KNOWN)}"
    )


def is_metered(provider: Provider) -> bool:
    """False for self-hosted endpoints, which have no per-token API charge."""
    return getattr(provider, "metered", True)


__all__ = [
    "KNOWN",
    "ChatResult",
    "Provider",
    "build",
    "cost_usd",
    "is_metered",
    "load_pricing",
]
