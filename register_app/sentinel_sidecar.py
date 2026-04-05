# -*- coding: utf-8 -*-
"""Sentinel JS sidecar wrapper."""

from __future__ import annotations

import base64
import json
import logging
import os
import shutil
import subprocess
from typing import Any, Dict, Iterable

logger = logging.getLogger("openai_register")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SIDECAR_PATH = os.path.join(_PROJECT_ROOT, "core", "sentinel_vm_sidecar.js")
_DEFAULT_SCRIPT_SOURCES = (
    "https://sentinel.openai.com/sentinel/20260219f9f6/sdk.js",
    "https://sentinel.openai.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
    "https://chatgpt.com/sentinel/20260219f9f6/sdk.js",
    "https://chatgpt.com/backend-api/sentinel/frame.html?sv=20260219f9f6",
)


def sentinel_vm_sidecar_available() -> bool:
    return bool(os.path.isfile(_SIDECAR_PATH) and shutil.which("node"))


def _normalize_script_sources(values: Iterable[str] | None) -> list[str]:
    result: list[str] = []
    for item in values or _DEFAULT_SCRIPT_SOURCES:
        value = str(item or "").strip()
        if value and value not in result:
            result.append(value)
    return result


def _decode_sidecar_value(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    try:
        return base64.b64decode(raw).decode("utf-8", "replace")
    except Exception:
        return ""


def _looks_like_vm_error(value: str) -> bool:
    decoded = _decode_sidecar_value(value)
    if not decoded:
        return False
    lowered = decoded.lower()
    return any(
        marker in lowered
        for marker in (
            "typeerror:",
            "referenceerror:",
            "syntaxerror:",
            "rangeerror:",
            "error:",
            "cannot read properties of undefined",
            "is not a function",
        )
    )


def run_sentinel_vm_sidecar(
    *,
    payload: Dict[str, Any],
    did: str,
    flow: str,
    requirements_token: str,
    proof: str = "",
    user_agent: str = "",
    script_sources: Iterable[str] | None = None,
    location_href: str = "https://chatgpt.com/auth/login?callbackUrl=%2F&screen_hint=signup",
    hardware_concurrency: int = 8,
    screen_sum: int = 3000,
    js_heap_size_limit: int = 4294705152,
    timeout_seconds: int = 30,
) -> Dict[str, Any]:
    """运行本地 Node Sentinel VM sidecar。

    失败时返回空 dict，不抛出异常，避免影响主注册链路。
    """
    if not sentinel_vm_sidecar_available():
        return {}

    stdin_payload = {
        "payload": payload or {},
        "did": str(did or "").strip(),
        "flow": str(flow or "").strip(),
        "requirements_token": str(requirements_token or "").strip(),
        "proof": str(proof or "").strip(),
        "user_agent": str(user_agent or "").strip(),
        "script_sources": _normalize_script_sources(script_sources),
        "location_href": str(location_href or "").strip(),
        "hardware_concurrency": max(1, int(hardware_concurrency or 8)),
        "screen_sum": max(1, int(screen_sum or 3000)),
        "js_heap_size_limit": max(1, int(js_heap_size_limit or 4294705152)),
    }
    try:
        completed = subprocess.run(
            ["node", _SIDECAR_PATH],
            input=json.dumps(stdin_payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_seconds)),
            cwd=_PROJECT_ROOT,
            check=False,
        )
    except Exception as exc:
        logger.warning(f"[警告] Sentinel VM sidecar 启动失败: {exc}")
        return {}

    stdout = str(completed.stdout or "").strip()
    stderr = str(completed.stderr or "").strip()
    if completed.returncode != 0:
        logger.warning(
            f"[警告] Sentinel VM sidecar 执行失败: returncode={completed.returncode}, stderr={stderr[:300]}"
        )
        return {}
    if not stdout:
        return {}

    line = stdout.splitlines()[-1].strip()
    try:
        result = json.loads(line)
    except Exception as exc:
        logger.warning(f"[警告] Sentinel VM sidecar 输出解析失败: {exc}; raw={line[:300]}")
        return {}
    if not isinstance(result, dict):
        return {}

    turnstile_value = str(result.get("turnstile_t") or "").strip()
    session_observer_raw = str(result.get("session_observer_raw") or "").strip()
    if turnstile_value and _looks_like_vm_error(turnstile_value):
        result["turnstile_error"] = _decode_sidecar_value(turnstile_value)[:500]
        result["turnstile_t"] = ""
        result["openai_sentinel_token"] = ""
    if session_observer_raw and _looks_like_vm_error(session_observer_raw):
        result["session_observer_error"] = _decode_sidecar_value(session_observer_raw)[:500]
        result["session_observer_raw"] = ""
        result["openai_sentinel_so_token"] = ""
    return result


__all__ = [
    "run_sentinel_vm_sidecar",
    "sentinel_vm_sidecar_available",
]


def generate_sentinel_requirements_token_via_sidecar(
    *,
    did: str,
    flow: str,
    user_agent: str = "",
    script_sources: Iterable[str] | None = None,
    location_href: str = "https://chatgpt.com/auth/login?callbackUrl=%2F&screen_hint=signup",
    hardware_concurrency: int = 8,
    screen_sum: int = 3000,
    js_heap_size_limit: int = 4294705152,
    timeout_seconds: int = 30,
) -> str:
    """通过 Node sidecar 生成 requirements token。"""
    if not sentinel_vm_sidecar_available():
        return ""
    stdin_payload = {
        "mode": "requirements",
        "did": str(did or "").strip(),
        "flow": str(flow or "").strip(),
        "user_agent": str(user_agent or "").strip(),
        "script_sources": _normalize_script_sources(script_sources),
        "location_href": str(location_href or "").strip(),
        "hardware_concurrency": max(1, int(hardware_concurrency or 8)),
        "screen_sum": max(1, int(screen_sum or 3000)),
        "js_heap_size_limit": max(1, int(js_heap_size_limit or 4294705152)),
    }
    try:
        completed = subprocess.run(
            ["node", _SIDECAR_PATH],
            input=json.dumps(stdin_payload, ensure_ascii=False),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(1, int(timeout_seconds)),
            cwd=_PROJECT_ROOT,
            check=False,
        )
    except Exception as exc:
        logger.warning(f"[警告] Sentinel requirements sidecar 启动失败: {exc}")
        return ""
    stdout = str(completed.stdout or "").strip()
    if completed.returncode != 0 or not stdout:
        return ""
    line = stdout.splitlines()[-1].strip()
    try:
        payload = json.loads(line)
    except Exception:
        return ""
    token = str((payload or {}).get("requirements_token") or "").strip()
    return token


__all__.append("generate_sentinel_requirements_token_via_sidecar")
