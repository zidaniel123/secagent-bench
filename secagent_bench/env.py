"""Minimal .env loader.

Hand-rolled rather than depending on python-dotenv: this is fifteen lines, and
a benchmark that people run once should not drag in a dependency for it.

Real environment variables always win. That way `ANTHROPIC_API_KEY=... command`
overrides the file for a one-off run without editing anything, and a key
exported in your shell is never silently shadowed by a stale .env.
"""

from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path = ".env") -> list[str]:
    """Load ``KEY=value`` lines into ``os.environ``. Returns the names set.

    Values are never logged or returned — only the variable names, so a caller
    can report "loaded 3 keys from .env" without putting secrets on screen.
    """
    p = Path(path)
    if not p.exists():
        return []

    loaded: list[str] = []
    for raw in p.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export ") :].strip()
        value = value.strip().strip('"').strip("'")
        # Strip a trailing inline comment on an unquoted value.
        if " #" in value and not raw.strip().endswith(value):
            value = value.split(" #", 1)[0].strip()
        if not key or not value:
            continue
        if key in os.environ and os.environ[key]:
            continue  # a real env var wins
        os.environ[key] = value
        loaded.append(key)
    return loaded
