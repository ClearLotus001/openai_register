"""Browser profile lifecycle helpers."""

from __future__ import annotations

from typing import Any, Dict, Optional

from .models import BrowserHandle, BrowserProfileConfig, BrowserRuntimeConfig
from .proxy import parse_proxy_url
from .roxy import RoxyClient


def is_roxy_configured(config: BrowserRuntimeConfig) -> bool:
    runtime = (config or BrowserRuntimeConfig()).normalized()
    return (
        runtime.backend == "roxy"
        and runtime.roxy_port > 0
        and bool(runtime.roxy_token)
        and runtime.roxy_workspace_id > 0
    )


def build_roxy_profile_payload(config: BrowserProfileConfig) -> Dict[str, Any]:
    proxy_info = parse_proxy_url(config.proxy_url)
    return {
        "workspaceId": int(config.workspace_id),
        "windowName": str(config.window_name or "").strip() or "openai_register",
        "coreVersion": str(config.core_version or "145").strip() or "145",
        "os": str(config.os_name or "macOS").strip() or "macOS",
        "proxyInfo": proxy_info,
        "fingerInfo": {
            "randomFingerprint": bool(config.random_fingerprint),
            "portScanProtect": bool(config.port_scan_protect),
        },
    }


def create_roxy_profile(client: RoxyClient, config: BrowserProfileConfig) -> str:
    result = client.browser_create(build_roxy_profile_payload(config))
    if result.get("code") != 0:
        raise RuntimeError(f"roxy create profile failed: {result}")

    data = result.get("data") or {}
    profile_id = str(data.get("dirId") or "").strip()
    if not profile_id:
        raise RuntimeError(f"roxy create profile missing dirId: {result}")
    return profile_id


def open_roxy_profile(
    client: RoxyClient,
    *,
    profile_id: str,
    launch_args: Optional[list[str]] = None,
    proxy_url: str = "",
    fingerprint_profile: str = "",
    metadata: Optional[Dict[str, Any]] = None,
) -> BrowserHandle:
    ws_endpoint = ""
    info = client.browser_connection_info([profile_id])
    for item in info.get("data") or []:
        ws_endpoint = str(item.get("wsEndpoint") or item.get("ws") or "").strip()
        if ws_endpoint:
            break

    if not ws_endpoint:
        result = client.browser_open(profile_id, args=list(launch_args or []))
        if result.get("code") != 0:
            raise RuntimeError(f"roxy open profile failed: {result}")

        data = result.get("data") or {}
        ws_endpoint = str(data.get("wsEndpoint") or data.get("ws") or "").strip()

    if not ws_endpoint:
        info = client.browser_connection_info([profile_id])
        for item in info.get("data") or []:
            ws_endpoint = str(item.get("wsEndpoint") or item.get("ws") or "").strip()
            if ws_endpoint:
                break
    if not ws_endpoint:
        raise RuntimeError(f"roxy open profile missing ws endpoint: {result}")

    return BrowserHandle(
        backend="roxy",
        profile_id=str(profile_id or "").strip(),
        ws_endpoint=ws_endpoint,
        proxy_url=str(proxy_url or "").strip(),
        fingerprint_profile=str(fingerprint_profile or "").strip(),
        metadata=dict(metadata or {}),
    )


def close_roxy_profile(client: RoxyClient, profile_id: str) -> Dict[str, Any]:
    return client.browser_close(profile_id)
