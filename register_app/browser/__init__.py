"""Browser backend helpers and runtime configuration."""

from .artifacts import build_screenshot_path, ensure_browser_artifacts, save_page_screenshot
from .models import (
    BrowserArtifacts,
    BrowserHandle,
    BrowserProfileConfig,
    BrowserRuntimeConfig,
    normalize_browser_backend,
    normalize_registration_engine,
)
from .profile import (
    build_roxy_profile_payload,
    close_roxy_profile,
    create_roxy_profile,
    is_roxy_configured,
    open_roxy_profile,
)
from .proxy import parse_proxy_url
from .roxy import RoxyClient
from .runtime import configure_browser_runtime, get_browser_runtime_config
from .session import open_cdp_page

__all__ = [
    "BrowserArtifacts",
    "BrowserHandle",
    "BrowserProfileConfig",
    "BrowserRuntimeConfig",
    "RoxyClient",
    "build_roxy_profile_payload",
    "build_screenshot_path",
    "close_roxy_profile",
    "configure_browser_runtime",
    "create_roxy_profile",
    "ensure_browser_artifacts",
    "get_browser_runtime_config",
    "is_roxy_configured",
    "normalize_browser_backend",
    "normalize_registration_engine",
    "open_cdp_page",
    "open_roxy_profile",
    "parse_proxy_url",
    "save_page_screenshot",
]
