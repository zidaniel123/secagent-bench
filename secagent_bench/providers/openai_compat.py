"""Every OpenAI-compatible backend: OpenAI, Moonshot (Kimi), Zhipu (GLM), and
any local model you serve yourself with vLLM or Ollama.

These all speak ``POST /v1/chat/completions``, so one adapter covers them and the
only thing that changes is the base URL, the key, and the model id. That is also
why a local model on your own GPU is a drop-in comparison against a frontier API:
same code path, same metrics.

Model ids move faster than this file does. Treat the defaults below as a starting
point and confirm them against the provider's current model list.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

from .base import ChatResult, Provider


@dataclass(frozen=True)
class Preset:
    """A named OpenAI-compatible endpoint."""

    base_url: str
    env_key: str
    default_model: str
    #: Local endpoints bill nothing; skip them in cost accounting.
    metered: bool = True


PRESETS: dict[str, Preset] = {
    "openai": Preset(
        base_url="https://api.openai.com/v1",
        env_key="OPENAI_API_KEY",
        default_model="gpt-5",
    ),
    "kimi": Preset(
        base_url="https://api.moonshot.ai/v1",
        env_key="MOONSHOT_API_KEY",
        default_model="kimi-k3",
    ),
    "glm": Preset(
        base_url="https://api.z.ai/api/paas/v4",
        env_key="ZHIPU_API_KEY",
        default_model="glm-4.6",
    ),
    # Anything you serve yourself. vLLM defaults to :8000, Ollama to :11434.
    "local": Preset(
        base_url="http://localhost:8000/v1",
        env_key="LOCAL_API_KEY",
        default_model="",  # no sensible default — name the model you loaded
        metered=False,
    ),
}


class OpenAICompatProvider(Provider):
    """One adapter, many endpoints."""

    def __init__(
        self,
        preset: str = "openai",
        model: str | None = None,
        **options: Any,
    ) -> None:
        if preset not in PRESETS:
            raise ValueError(
                f"Unknown preset {preset!r}. Known: {', '.join(sorted(PRESETS))}"
            )
        self.preset_name = preset
        self.preset = PRESETS[preset]

        resolved_model = model or self.preset.default_model
        if not resolved_model:
            raise ValueError(
                f"Preset {preset!r} has no default model — set `model:` in your "
                "config to the model you are serving."
            )
        super().__init__(resolved_model, **options)
        self.name = preset

        try:
            from openai import OpenAI
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError(
                "The openai SDK is required for OpenAI-compatible providers. "
                "Install it with: pip install 'secagent-bench[openai]'"
            ) from exc

        base_url = options.get("base_url") or os.getenv(
            f"{preset.upper()}_BASE_URL", self.preset.base_url
        )
        # Self-hosted servers usually ignore the key but the client demands one.
        api_key = (
            options.get("api_key")
            or os.getenv(self.preset.env_key)
            or ("EMPTY" if not self.preset.metered else None)
        )
        if not api_key:
            raise RuntimeError(
                f"No API key for {preset!r}. Set ${self.preset.env_key}."
            )

        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=600.0)
        self.temperature: float | None = options.get("temperature", 0.0)

    @property
    def metered(self) -> bool:
        return self.preset.metered

    def _complete(self, system: str, user: str, max_tokens: int) -> ChatResult:
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        # temperature=0 where supported keeps re-runs comparable. Some reasoning
        # models reject the parameter outright; drop it and retry rather than
        # scoring the model as an error.
        if self.temperature is not None:
            kwargs["temperature"] = self.temperature
        try:
            response = self._client.chat.completions.create(**kwargs)
        except Exception as exc:  # noqa: BLE001
            if self.temperature is None or "temperature" not in str(exc).lower():
                raise
            kwargs.pop("temperature")
            response = self._client.chat.completions.create(**kwargs)

        choice = response.choices[0]
        text = choice.message.content or ""

        # OpenAI's schema carries an explicit refusal field; most compatible
        # servers do not. Where it is absent, refusal is detected downstream by
        # secagent_bench.scoring.looks_like_refusal.
        refusal = getattr(choice.message, "refusal", None)

        usage = response.usage
        return ChatResult(
            text=text if not refusal else "",
            provider=self.name,
            model=self.model,
            input_tokens=getattr(usage, "prompt_tokens", 0) if usage else 0,
            output_tokens=getattr(usage, "completion_tokens", 0) if usage else 0,
            hard_refusal=bool(refusal),
            refusal_category="provider_refusal" if refusal else None,
            raw={"finish_reason": choice.finish_reason, "refusal": refusal},
        )
