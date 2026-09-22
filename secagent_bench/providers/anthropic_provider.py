"""Anthropic (Claude) via the official SDK.

Claude gets a first-class adapter rather than going through the OpenAI-compatible
path, for one reason that matters to this benchmark: it reports refusals
*structurally*. When a safety classifier declines, the call returns HTTP 200 with
``stop_reason == "refusal"`` and a ``stop_details.category`` — so refusal rate on
Claude is measured, not inferred from string matching like everywhere else.
"""

from __future__ import annotations

import os
from typing import Any

from .base import ChatResult, Provider

#: Default model. Claude Opus 5 runs adaptive thinking when `thinking` is omitted.
DEFAULT_MODEL = "claude-opus-5"


class AnthropicProvider(Provider):
    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL, **options: Any) -> None:
        super().__init__(model, **options)
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "The anthropic SDK is required for the Claude provider. "
                "Install it with: pip install 'secagent-bench[anthropic]'"
            ) from exc

        api_key = options.get("api_key") or os.getenv("ANTHROPIC_API_KEY")
        # A bare Anthropic() also resolves an `ant auth login` profile, so an
        # unset ANTHROPIC_API_KEY is not necessarily an error.
        self._client = anthropic.Anthropic(**({"api_key": api_key} if api_key else {}))
        self._anthropic = anthropic

        #: low | medium | high | xhigh | max. Left unset, the API default (high)
        #: applies. Raise it for hard analysis, drop it to cut spend.
        self.effort: str | None = options.get("effort")

    def _complete(self, system: str, user: str, max_tokens: int) -> ChatResult:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }
        if self.effort:
            kwargs["output_config"] = {"effort": self.effort}

        response = self._client.messages.create(**kwargs)

        # A refusal is a successful HTTP call with no usable content. Check the
        # stop reason before reading content.
        hard_refusal = response.stop_reason == "refusal"
        category = None
        if hard_refusal and getattr(response, "stop_details", None):
            category = getattr(response.stop_details, "category", None)

        text = "".join(
            block.text for block in response.content if block.type == "text"
        )

        return ChatResult(
            text=text,
            provider=self.name,
            model=self.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            hard_refusal=hard_refusal,
            refusal_category=category,
            raw={
                "stop_reason": response.stop_reason,
                "cache_read_input_tokens": getattr(
                    response.usage, "cache_read_input_tokens", 0
                ),
            },
        )
