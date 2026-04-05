"""Lightweight doctor and status helpers for the CLI entrypoint."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any

from curl_cffi import requests

from .browser import BrowserRuntimeConfig, RoxyClient, is_roxy_configured
from .config import load_config_file
from .mail.cfmail import cfmail_account_names, get_cfmail_accounts, select_cfmail_account
from .runtime import count_json_files

TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"


@dataclass(frozen=True)
class DoctorCheck:
    name: str
    status: str
    summary: str
    detail: str = ""


@dataclass(frozen=True)
class DoctorReport:
    checked_at: str
    checks: list[DoctorCheck]

    @property
    def error_count(self) -> int:
        return sum(1 for item in self.checks if item.status == "error")

    @property
    def warn_count(self) -> int:
        return sum(1 for item in self.checks if item.status == "warn")


def _configured_mail_providers(args: Any) -> list[str]:
    value = getattr(args, "mail_providers", None)
    if isinstance(value, (list, tuple, set)):
        items = [str(item or "").strip().lower() for item in value if str(item or "").strip()]
        if items:
            return items
    provider = str(getattr(args, "mail_provider", "") or "").strip().lower()
    return [provider] if provider else []


def _browser_runtime_from_args(args: Any) -> BrowserRuntimeConfig:
    return BrowserRuntimeConfig(
        registration_engine=getattr(args, "registration_engine", "http"),
        backend=getattr(args, "browser_backend", "roxy"),
        roxy_port=getattr(args, "roxy_port", 50000),
        roxy_token=getattr(args, "roxy_token", ""),
        roxy_workspace_id=getattr(args, "roxy_workspace_id", 0),
        core_version=getattr(args, "browser_core_version", "145"),
        os_name=getattr(args, "browser_os", "macOS"),
        keep_profile_for_oauth=getattr(args, "browser_keep_profile_for_oauth", True),
        screenshots_enabled=getattr(args, "browser_screenshots_enabled", True),
        asset_cache_enabled=getattr(args, "browser_asset_cache_enabled", False),
    ).normalized()


def _is_patchright_importable() -> tuple[bool, str]:
    try:
        import patchright.async_api  # noqa: F401
    except Exception as exc:
        return False, str(exc)
    return True, "ok"


def _stringify_detail(value: Any, *, limit: int = 240) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _extract_roxy_workspace_ids(payload: Any) -> set[int]:
    workspace_ids: set[int] = set()
    candidates = payload
    if isinstance(payload, dict):
        candidates = payload.get("data", payload)
    if not isinstance(candidates, list):
        candidates = [candidates]

    for item in candidates:
        if not isinstance(item, dict):
            continue
        for key in ("workspaceId", "id"):
            try:
                value = int(item.get(key) or 0)
            except Exception:
                value = 0
            if value > 0:
                workspace_ids.add(value)
    return workspace_ids


def _check_config_file(config_path: str) -> DoctorCheck:
    path = str(config_path or "").strip()
    if not path:
        return DoctorCheck("config", "warn", "未指定配置文件路径，将仅使用默认参数")
    if not os.path.exists(path):
        return DoctorCheck("config", "warn", f"配置文件不存在：{path}；将使用默认参数")
    if not os.path.isfile(path):
        return DoctorCheck("config", "error", f"配置路径不是文件：{path}")
    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            payload = json.load(file_obj)
        if not isinstance(payload, dict):
            return DoctorCheck("config", "error", f"配置文件不是 JSON object：{path}")
        filtered = load_config_file(path)
        return DoctorCheck(
            "config",
            "ok",
            f"配置文件可读：{path}",
            detail=f"键数量={len(filtered)}",
        )
    except Exception as exc:
        return DoctorCheck("config", "error", f"读取配置文件失败：{path}", detail=str(exc))


def _touch_directory(path: str) -> tuple[bool, str]:
    try:
        os.makedirs(path, exist_ok=True)
        with tempfile.NamedTemporaryFile(prefix=".doctor-", dir=path, delete=True):
            pass
    except Exception as exc:
        return False, str(exc)
    return True, "ok"


def _check_directory(name: str, path: str) -> DoctorCheck:
    target = str(path or "").strip()
    if not target:
        return DoctorCheck(name, "error", f"{name} 未配置")
    ok, detail = _touch_directory(target)
    if not ok:
        return DoctorCheck(name, "error", f"{name} 不可写：{target}", detail=detail)
    count = count_json_files(target)
    return DoctorCheck(name, "ok", f"{name} 可用：{target}", detail=f"当前 json 数量={count}")


def _parse_trace(text: str) -> dict[str, str]:
    payload: dict[str, str] = {}
    for line in str(text or "").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip()
    return payload


def _check_proxy(proxy: str | None) -> DoctorCheck:
    proxy_url = str(proxy or "").strip()
    if not proxy_url:
        return DoctorCheck("proxy", "warn", "未显式设置 proxy，将按当前直连环境运行")

    try:
        resp = requests.get(
            TRACE_URL,
            proxies={"http": proxy_url, "https": proxy_url},
            impersonate="chrome",
            timeout=10,
        )
    except Exception as exc:
        return DoctorCheck("proxy", "error", f"代理不可达：{proxy_url}", detail=str(exc))

    if resp.status_code != 200:
        return DoctorCheck(
            "proxy",
            "error",
            f"代理探测失败：HTTP {resp.status_code}",
            detail=str(getattr(resp, "text", "") or "")[:240],
        )

    trace = _parse_trace(getattr(resp, "text", ""))
    loc = trace.get("loc") or "unknown"
    ip = trace.get("ip") or ""
    return DoctorCheck("proxy", "ok", f"代理可用：{proxy_url}", detail=f"出口地区={loc} ip={ip}")


def _check_cfmail(args: Any) -> DoctorCheck:
    selected_providers = _configured_mail_providers(args)
    if "cfmail" not in selected_providers:
        return DoctorCheck(
            "cfmail",
            "skip",
            f"当前邮箱服务为 {','.join(selected_providers) or args.mail_provider}，跳过 cfmail 检查",
        )

    accounts = get_cfmail_accounts()
    if not accounts:
        return DoctorCheck(
            "cfmail",
            "error",
            f"未检测到可用 cfmail 配置：{args.cfmail_config}",
        )

    selected = select_cfmail_account(args.cfmail_profile)
    if str(args.cfmail_profile or "").strip().lower() != "auto" and selected is None:
        return DoctorCheck(
            "cfmail",
            "error",
            f"指定的 cfmail profile 不存在：{args.cfmail_profile}",
            detail=f"当前可用：{cfmail_account_names(accounts)}",
        )

    active = selected or accounts[0]
    return DoctorCheck(
        "cfmail",
        "ok",
        f"cfmail 已配置：{active.name} -> {active.email_domain}",
        detail=f"配置数={len(accounts)}",
    )


def _check_browser_runtime(args: Any) -> list[DoctorCheck]:
    runtime = _browser_runtime_from_args(args)
    detail = (
        f"engine={runtime.registration_engine} backend={runtime.backend} "
        f"port={runtime.roxy_port} workspace_id={runtime.roxy_workspace_id}"
    )

    if runtime.registration_engine == "http":
        return [
            DoctorCheck(
                "browser",
                "skip",
                "registration_engine=http，跳过浏览器运行时检查",
                detail=detail,
            )
        ]

    checks: list[DoctorCheck] = []
    if not is_roxy_configured(runtime):
        return [
            DoctorCheck(
                "browser_config",
                "error",
                "浏览器模式已启用，但 Roxy 配置不完整",
                detail=(
                    f"{detail} token_set={'yes' if bool(runtime.roxy_token) else 'no'} "
                    f"workspace_valid={'yes' if runtime.roxy_workspace_id > 0 else 'no'}"
                ),
            )
        ]

    checks.append(
        DoctorCheck(
            "browser_config",
            "ok",
            "浏览器运行时配置已启用",
            detail=(
                f"{detail} keep_profile_for_oauth={runtime.keep_profile_for_oauth} "
                f"screenshots_enabled={runtime.screenshots_enabled}"
            ),
        )
    )

    patchright_ok, patchright_detail = _is_patchright_importable()
    checks.append(
        DoctorCheck(
            "browser_patchright",
            "ok" if patchright_ok else "error",
            "patchright 可导入" if patchright_ok else "patchright 不可导入",
            detail=_stringify_detail(patchright_detail),
        )
    )

    client = RoxyClient(port=runtime.roxy_port, token=runtime.roxy_token)
    try:
        health = client.health()
    except Exception as exc:
        checks.append(
            DoctorCheck(
                "browser_roxy_health",
                "error",
                f"Roxy API 不可达：127.0.0.1:{runtime.roxy_port}",
                detail=_stringify_detail(exc),
            )
        )
        return checks

    checks.append(
        DoctorCheck(
            "browser_roxy_health",
            "ok",
            f"Roxy API 可达：127.0.0.1:{runtime.roxy_port}",
            detail=_stringify_detail(json.dumps(health, ensure_ascii=False)),
        )
    )

    try:
        workspaces = client.workspace_project()
    except Exception as exc:
        checks.append(
            DoctorCheck(
                "browser_roxy_workspace",
                "warn",
                "无法获取 Roxy workspace 列表",
                detail=_stringify_detail(exc),
            )
        )
        return checks

    workspace_ids = _extract_roxy_workspace_ids(workspaces)
    if workspace_ids and runtime.roxy_workspace_id not in workspace_ids:
        checks.append(
            DoctorCheck(
                "browser_roxy_workspace",
                "error",
                f"未在 Roxy workspace 列表中找到目标 workspaceId={runtime.roxy_workspace_id}",
                detail=f"可用 workspaceIds={sorted(workspace_ids)}",
            )
        )
    elif workspace_ids:
        checks.append(
            DoctorCheck(
                "browser_roxy_workspace",
                "ok",
                f"Roxy workspace 有效：{runtime.roxy_workspace_id}",
                detail=f"可用 workspaceIds={sorted(workspace_ids)}",
            )
        )
    else:
        checks.append(
            DoctorCheck(
                "browser_roxy_workspace",
                "warn",
                "Roxy workspace 列表返回成功，但未能解析 workspaceId",
                detail=_stringify_detail(json.dumps(workspaces, ensure_ascii=False)),
            )
        )

    return checks


def collect_doctor_report(args: Any) -> DoctorReport:
    checks = [
        _check_config_file(args.config),
        _check_directory("active_token_dir", args.active_token_dir),
        _check_proxy(args.proxy),
        _check_cfmail(args),
    ]
    checks.extend(_check_browser_runtime(args))
    return DoctorReport(
        checked_at=datetime.now().astimezone().isoformat(timespec="seconds"),
        checks=checks,
    )


def build_status_snapshot(args: Any) -> dict[str, Any]:
    browser_runtime = _browser_runtime_from_args(args)
    patchright_ok, patchright_detail = _is_patchright_importable()
    selected_providers = _configured_mail_providers(args)
    active_count = count_json_files(args.active_token_dir)
    active_shortage = max(int(args.active_min_count) - active_count, 0)
    snapshot: dict[str, Any] = {
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "config_path": str(args.config or "").strip(),
        "proxy": str(args.proxy or "").strip(),
        "mail_provider": str(args.mail_provider or "").strip(),
        "mail_providers": selected_providers,
        "active": {
            "dir": str(args.active_token_dir or "").strip(),
            "count": active_count,
            "target": int(args.active_min_count),
            "shortage": active_shortage,
        },
        "output": {
            "dir": str(args.token_dir or "").strip(),
        },
        "runtime": {
            "register_batch_size": int(args.register_batch_size),
            "register_openai_concurrency": int(args.register_openai_concurrency),
            "register_start_delay_seconds": float(args.register_start_delay_seconds),
            "monitor_interval": int(args.monitor_interval),
            "detected_total_memory_mb": int(getattr(args, "detected_total_memory_mb", 0) or 0),
        },
        "browser": {
            "registration_engine": browser_runtime.registration_engine,
            "backend": browser_runtime.backend,
            "roxy_port": browser_runtime.roxy_port,
            "roxy_workspace_id": browser_runtime.roxy_workspace_id,
            "roxy_token_set": bool(browser_runtime.roxy_token),
            "configured": is_roxy_configured(browser_runtime),
            "core_version": browser_runtime.core_version,
            "os_name": browser_runtime.os_name,
            "keep_profile_for_oauth": browser_runtime.keep_profile_for_oauth,
            "screenshots_enabled": browser_runtime.screenshots_enabled,
            "asset_cache_enabled": browser_runtime.asset_cache_enabled,
            "patchright_importable": patchright_ok,
            "patchright_detail": "" if patchright_ok else _stringify_detail(patchright_detail),
        },
    }

    if "cfmail" in selected_providers:
        accounts = get_cfmail_accounts()
        selected = select_cfmail_account(args.cfmail_profile)
        snapshot["cfmail"] = {
            "config_path": str(args.cfmail_config or "").strip(),
            "profile_mode": str(args.cfmail_profile or "").strip(),
            "selected": getattr(selected, "name", "") if selected else "",
            "accounts": [
                {
                    "name": item.name,
                    "worker_domain": item.worker_domain,
                    "email_domain": item.email_domain,
                }
                for item in accounts
            ],
        }

    return snapshot


def print_doctor_report(report: DoctorReport, *, output_json: bool = False) -> None:
    if output_json:
        payload = {
            "checked_at": report.checked_at,
            "error_count": report.error_count,
            "warn_count": report.warn_count,
            "checks": [asdict(item) for item in report.checks],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return

    print("doctor 检查结果")
    print(f"时间：{report.checked_at}")
    for item in report.checks:
        print(f"[{item.status.upper()}] {item.name}: {item.summary}")
        if item.detail:
            print(f"  └─ {item.detail}")
    print(f"汇总：error={report.error_count} warn={report.warn_count}")


def print_status_snapshot(snapshot: dict[str, Any], *, output_json: bool = False) -> None:
    if output_json:
        print(json.dumps(snapshot, ensure_ascii=False, indent=2))
        return

    print("当前状态")
    print(f"时间：{snapshot.get('checked_at', '')}")
    print(f"配置：{snapshot.get('config_path', '') or '(默认/未指定)'}")
    print(f"代理：{snapshot.get('proxy', '') or '(未显式设置)'}")
    providers = snapshot.get("mail_providers") or []
    provider_text = ",".join(str(item or "") for item in providers) if providers else snapshot.get("mail_provider", "")
    print(f"邮箱服务：{provider_text}")

    active = snapshot.get("active") or {}
    output = snapshot.get("output") or {}
    runtime = snapshot.get("runtime") or {}
    print(
        f"A目录：{active.get('count', 0)}/{active.get('target', 0)} "
        f"（缺 {active.get('shortage', 0)}） -> {active.get('dir', '')}"
    )
    print(f"注册输出目录：{output.get('dir', '')}")
    print(
        "并发："
        f"register_batch_size={runtime.get('register_batch_size', 0)}, "
        f"register_openai_concurrency={runtime.get('register_openai_concurrency', 0)}"
    )
    browser = snapshot.get("browser") or {}
    print(
        "浏览器："
        f"engine={browser.get('registration_engine', '')} "
        f"backend={browser.get('backend', '')} "
        f"configured={browser.get('configured', False)} "
        f"workspace_id={browser.get('roxy_workspace_id', 0)} "
        f"patchright={browser.get('patchright_importable', False)}"
    )
    if snapshot.get("cfmail"):
        cfmail = snapshot["cfmail"]
        account_names = ",".join(item.get("name", "") for item in cfmail.get("accounts", []))
        print(
            f"cfmail：profile={cfmail.get('profile_mode', '')} "
            f"selected={cfmail.get('selected', '') or '(auto)'} "
            f"accounts=[{account_names}]"
        )
