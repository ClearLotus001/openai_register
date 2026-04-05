"""Global browser runtime configuration."""

from __future__ import annotations

from .models import BrowserRuntimeConfig

_RUNTIME_CONFIG = BrowserRuntimeConfig().normalized()


def configure_browser_runtime(config: BrowserRuntimeConfig) -> BrowserRuntimeConfig:
    global _RUNTIME_CONFIG
    _RUNTIME_CONFIG = (config or BrowserRuntimeConfig()).normalized()
    return _RUNTIME_CONFIG


def get_browser_runtime_config() -> BrowserRuntimeConfig:
    return _RUNTIME_CONFIG
