"""Browser runtime and profile models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Tuple


def normalize_registration_engine(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized in {"browser", "hybrid"}:
        return normalized
    return "http"


def normalize_browser_backend(value: str) -> str:
    normalized = str(value or "").strip().lower()
    if normalized == "roxy":
        return normalized
    return "roxy"


@dataclass(frozen=True)
class BrowserRuntimeConfig:
    registration_engine: str = "http"
    backend: str = "roxy"
    roxy_port: int = 50000
    roxy_token: str = ""
    roxy_workspace_id: int = 0
    core_version: str = "145"
    os_name: str = "macOS"
    keep_profile_for_oauth: bool = True
    screenshots_enabled: bool = True
    asset_cache_enabled: bool = False

    def normalized(self) -> "BrowserRuntimeConfig":
        return BrowserRuntimeConfig(
            registration_engine=normalize_registration_engine(self.registration_engine),
            backend=normalize_browser_backend(self.backend),
            roxy_port=max(1, int(self.roxy_port or 50000)),
            roxy_token=str(self.roxy_token or "").strip(),
            roxy_workspace_id=max(0, int(self.roxy_workspace_id or 0)),
            core_version=str(self.core_version or "145").strip() or "145",
            os_name=str(self.os_name or "macOS").strip() or "macOS",
            keep_profile_for_oauth=bool(self.keep_profile_for_oauth),
            screenshots_enabled=bool(self.screenshots_enabled),
            asset_cache_enabled=bool(self.asset_cache_enabled),
        )

    @property
    def browser_enabled(self) -> bool:
        return self.registration_engine in {"browser", "hybrid"}


@dataclass(frozen=True)
class BrowserProfileConfig:
    window_name: str
    workspace_id: int
    proxy_url: str = ""
    core_version: str = "145"
    os_name: str = "macOS"
    random_fingerprint: bool = True
    port_scan_protect: bool = False
    launch_args: Tuple[str, ...] = ()
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BrowserHandle:
    backend: str
    profile_id: str
    ws_endpoint: str
    proxy_url: str = ""
    fingerprint_profile: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BrowserArtifacts:
    root_dir: str
    screenshots_dir: str
    logs_dir: str
