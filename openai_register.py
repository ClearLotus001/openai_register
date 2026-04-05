# -*- coding: utf-8 -*-
"""OpenAI 自动注册与账号巡检脚本。

支持多种临时邮箱服务，自动完成注册流程并维护 A 目录账号池。

本文件仅作为 CLI 入口：
- 核心注册流程 → register_app/registration/
- OAuth / Token 链路 → register_app/auth/
- Sentinel/指纹 → register_app/sentinel.py
- 邮箱 / cfmail → register_app/mail/
- 常量/配置管理 → register_app/config.py
"""
import argparse
import builtins
import json
import logging
import os
import subprocess
import sys
import threading
import time

from register_app.browser import BrowserRuntimeConfig, configure_browser_runtime
from register_app.doctor import (
    build_status_snapshot,
    collect_doctor_report,
    print_doctor_report,
    print_status_snapshot,
)
from register_app.mail.cfmail import (
    CfmailAccount,
    DEFAULT_CFMAIL_ACCOUNTS,
    DEFAULT_CFMAIL_CONFIG_PATH,
    DEFAULT_CFMAIL_COOLDOWN_SECONDS,
    DEFAULT_CFMAIL_FAIL_THRESHOLD,
    build_cfmail_accounts as _build_cfmail_accounts,
    cfmail_account_names as _cfmail_account_names,
    configure_cfmail_runtime,
    get_cfmail_accounts,
    load_cfmail_accounts_from_file as _load_cfmail_accounts_from_file,
    normalize_host as _normalize_host,
    reload_cfmail_accounts_if_needed as _reload_cfmail_accounts_if_needed,
    run_cfmail_self_test,
    select_cfmail_account as _select_cfmail_account,
)
from register_app.config import (
    DEFAULT_ACTIVE_TOKEN_DIR,
    DEFAULT_BROWSER_ASSET_CACHE_ENABLED,
    DEFAULT_BROWSER_BACKEND,
    DEFAULT_BROWSER_CORE_VERSION,
    DEFAULT_BROWSER_KEEP_PROFILE_FOR_OAUTH,
    DEFAULT_BROWSER_OS,
    DEFAULT_BROWSER_SCREENSHOTS_ENABLED,
    DEFAULT_CHECK_INTERVAL_SECONDS,
    DEFAULT_CONFIG_PATH,
    DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
    DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS,
    DEFAULT_DINGTALK_WEBHOOK,
    DEFAULT_MIN_ACTIVE_COUNT,
    DEFAULT_REGISTRATION_ENGINE,
    DEFAULT_REGISTER_BATCH_SIZE,
    DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS,
    DEFAULT_REGISTER_OPENAI_CONCURRENCY,
    DEFAULT_REGISTER_START_DELAY_SECONDS,
    DEFAULT_ROXY_PORT,
    DEFAULT_ROXY_TOKEN,
    DEFAULT_ROXY_WORKSPACE_ID,
    DEFAULT_TOKEN_OUTPUT_DIR,
    apply_config_to_args,
    apply_low_memory_tuning,
    collect_explicit_cli_dests,
    load_config_file,
)
from register_app.registration import run_with_fallback
from register_app.mail.providers import MAILTM_BASE
from register_app.runtime import (
    log_info,
    run_monitor_loop,
    worker,
)

logger = logging.getLogger("openai_register")

builtins.yasal_bypass_ip_choice = True

SUPPORTED_MAIL_PROVIDERS = ("cfmail", "tempmaillol", "mailtm", "tempmailio", "dropmail")


def _parse_mail_providers(raw_value: object, fallback_single: str) -> list[str]:
    items: list[str] = []
    if isinstance(raw_value, (list, tuple, set)):
        candidates = raw_value
    else:
        text = str(raw_value or "").strip()
        candidates = text.split(",") if text else []

    for item in candidates:
        value = str(item or "").strip().lower()
        if not value:
            continue
        if value not in SUPPORTED_MAIL_PROVIDERS:
            raise ValueError(f"不支持的邮箱服务: {value}")
        if value not in items:
            items.append(value)

    fallback = str(fallback_single or "").strip().lower()
    if not items and fallback:
        if fallback not in SUPPORTED_MAIL_PROVIDERS:
            raise ValueError(f"不支持的邮箱服务: {fallback}")
        items.append(fallback)

    return items or ["cfmail"]


def _resolve_cfmail_process_profiles(selected_profile: str) -> list[str]:
    accounts = get_cfmail_accounts()
    if not accounts:
        return []

    profile_name = str(selected_profile or "auto").strip() or "auto"
    if profile_name.lower() != "auto":
        matched = _select_cfmail_account(profile_name)
        return [matched.name] if matched else []

    return [account.name for account in accounts if str(account.name or "").strip()]


def _build_cfmail_profile_worker_command(
    args: argparse.Namespace,
    *,
    profile_name: str,
    sleep_min: int,
    sleep_max: int,
) -> list[str]:
    command = [
        sys.executable,
        os.path.abspath(__file__),
        "--config",
        str(args.config),
        "--register-only",
        "--mail-provider",
        "cfmail",
        "--cfmail-config",
        str(args.cfmail_config),
        "--cfmail-profile",
        str(profile_name),
        "--sleep-min",
        str(sleep_min),
        "--sleep-max",
        str(sleep_max),
        "--failure-sleep-seconds",
        str(args.failure_sleep_seconds),
        "--mailtm-api-base",
        str(args.mailtm_api_base),
        "--token-dir",
        str(args.token_dir),
        "--register-openai-concurrency",
        "1",
        "--register-start-delay-seconds",
        "0",
        "--dingtalk-fallback-interval",
        str(args.dingtalk_fallback_interval),
        "--cfmail-fail-threshold",
        str(args.cfmail_fail_threshold),
        "--cfmail-cooldown-seconds",
        str(args.cfmail_cooldown_seconds),
    ]

    if args.proxy:
        command.extend(["--proxy", str(args.proxy)])
    if args.once:
        command.append("--once")
    if args.auto_continue_non_us:
        command.append("--auto-continue-non-us")
    if args.dingtalk_webhook:
        command.extend(["--dingtalk-webhook", str(args.dingtalk_webhook)])

    return command


def _run_cfmail_profile_processes(
    args: argparse.Namespace,
    *,
    sleep_min: int,
    sleep_max: int,
) -> bool:
    profile_names = _resolve_cfmail_process_profiles(args.cfmail_profile)
    if len(profile_names) <= 1:
        return False

    script_dir = os.path.dirname(os.path.abspath(__file__))
    processes: list[tuple[str, subprocess.Popen]] = []
    log_info(
        f"cfmail 多配置注册模式启动：共 {len(profile_names)} 个独立进程，配置={', '.join(profile_names)}"
    )

    try:
        for index, profile_name in enumerate(profile_names, start=1):
            command = _build_cfmail_profile_worker_command(
                args,
                profile_name=profile_name,
                sleep_min=sleep_min,
                sleep_max=sleep_max,
            )
            process = subprocess.Popen(command, cwd=script_dir)
            processes.append((profile_name, process))
            log_info(
                f"[父进程] 已启动 cfmail 子进程 #{index}：profile={profile_name} pid={process.pid}"
            )
            if args.register_start_delay_seconds > 0 and index < len(profile_names):
                time.sleep(args.register_start_delay_seconds)

        while processes:
            alive_processes: list[tuple[str, subprocess.Popen]] = []
            for profile_name, process in processes:
                return_code = process.poll()
                if return_code is None:
                    alive_processes.append((profile_name, process))
                    continue
                log_info(
                    f"[父进程] cfmail 子进程已退出：profile={profile_name} pid={process.pid} code={return_code}"
                )

            if not alive_processes:
                break

            processes = alive_processes
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\n[信息] 收到中断信号，准备停止所有 cfmail 子进程")
        for _profile_name, process in processes:
            if process.poll() is not None:
                continue
            process.terminate()
        deadline = time.time() + 10
        for _profile_name, process in processes:
            remaining_seconds = max(0.0, deadline - time.time())
            try:
                process.wait(timeout=remaining_seconds)
            except subprocess.TimeoutExpired:
                process.kill()
    return True


def main() -> None:
    """CLI 入口函数。"""
    parser = argparse.ArgumentParser(description="OpenAI 自动注册与账号巡检脚本")
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"JSON 配置文件路径，默认 {DEFAULT_CONFIG_PATH}",
    )
    parser.add_argument(
        "--proxy", default=None, help="代理地址，如 http://127.0.0.1:7890"
    )
    parser.add_argument(
        "--registration-engine",
        default=DEFAULT_REGISTRATION_ENGINE,
        choices=["http", "browser", "hybrid"],
        help="注册引擎：http / browser / hybrid（当前 phase 1 默认仍会走 HTTP）",
    )
    parser.add_argument(
        "--browser-backend",
        default=DEFAULT_BROWSER_BACKEND,
        choices=["roxy"],
        help="浏览器后端，当前支持 roxy",
    )
    parser.add_argument(
        "--roxy-port",
        type=int,
        default=DEFAULT_ROXY_PORT,
        help="RoxyBrowser API 端口",
    )
    parser.add_argument(
        "--roxy-token",
        default=DEFAULT_ROXY_TOKEN,
        help="RoxyBrowser API token",
    )
    parser.add_argument(
        "--roxy-workspace-id",
        type=int,
        default=DEFAULT_ROXY_WORKSPACE_ID,
        help="RoxyBrowser workspaceId",
    )
    parser.add_argument(
        "--browser-core-version",
        default=DEFAULT_BROWSER_CORE_VERSION,
        help="浏览器 profile coreVersion",
    )
    parser.add_argument(
        "--browser-os",
        default=DEFAULT_BROWSER_OS,
        help="浏览器 profile 操作系统标识，如 macOS / Windows",
    )
    parser.add_argument(
        "--browser-keep-profile-for-oauth",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_BROWSER_KEEP_PROFILE_FOR_OAUTH,
        help="浏览器注册成功后是否保留 profile 供 OAuth 复用",
    )
    parser.add_argument(
        "--browser-screenshots-enabled",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_BROWSER_SCREENSHOTS_ENABLED,
        help="是否启用浏览器截图调试输出",
    )
    parser.add_argument(
        "--browser-asset-cache-enabled",
        action=argparse.BooleanOptionalAction,
        default=DEFAULT_BROWSER_ASSET_CACHE_ENABLED,
        help="是否启用浏览器静态资源缓存",
    )
    parser.add_argument("--once", action="store_true", help="注册模式只运行一次")
    parser.add_argument(
        "--sleep-min", type=int, default=10, help="注册循环最短等待秒数"
    )
    parser.add_argument(
        "--sleep-max", type=int, default=30, help="注册循环最长等待秒数"
    )
    parser.add_argument(
        "--failure-sleep-seconds",
        type=int,
        default=DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS,
        help="注册失败后额外等待秒数",
    )
    parser.add_argument(
        "--mail-provider",
        default="cfmail",
        choices=list(SUPPORTED_MAIL_PROVIDERS),
        help="邮箱服务（cfmail / tempmaillol / mailtm / tempmailio / dropmail）",
    )
    parser.add_argument(
        "--mail-providers",
        default="",
        help="多个邮箱服务并行注册，逗号分隔；如 cfmail,tempmaillol,mailtm",
    )
    parser.add_argument(
        "--cfmail-profile",
        default="auto",
        help="自建邮箱配置名；auto 表示按 cfmail 配置文件中的顺序轮询",
    )
    parser.add_argument(
        "--cfmail-config",
        default=DEFAULT_CFMAIL_CONFIG_PATH,
        help="cfmail 邮箱配置 JSON 文件路径",
    )
    parser.add_argument(
        "--cfmail-worker-domain",
        default=None,
        help="临时覆盖自建邮箱后端域名，如 apimail.example.com",
    )
    parser.add_argument(
        "--cfmail-email-domain",
        default=None,
        help="临时覆盖自建邮箱域名，如 example.com",
    )
    parser.add_argument(
        "--cfmail-admin-password",
        default=None,
        help="临时覆盖自建邮箱后台管理员密码",
    )
    parser.add_argument(
        "--cfmail-profile-name",
        default="custom",
        help="临时覆盖自建邮箱配置时使用的配置名",
    )
    parser.add_argument(
        "--mailtm-api-base",
        default=MAILTM_BASE,
        help="Mail.tm API 地址（可替换为兼容 Mail.tm 的自建服务）",
    )
    parser.add_argument(
        "--token-dir",
        default=DEFAULT_TOKEN_OUTPUT_DIR,
        help="注册模式 Token 输出目录",
    )
    parser.add_argument(
        "--active-token-dir",
        default=DEFAULT_ACTIVE_TOKEN_DIR,
        help="A 目录，当前正在使用的账号目录",
    )
    parser.add_argument(
        "--active-min-count",
        type=int,
        default=DEFAULT_MIN_ACTIVE_COUNT,
        help="A 目录最少保留数量",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="持续巡检模式：每隔一段时间检查 A 目录数量并自动补号",
    )
    parser.add_argument(
        "--monitor-once",
        action="store_true",
        help="巡检模式只执行一轮",
    )
    parser.add_argument(
        "--register-only",
        action="store_true",
        help="仅执行注册逻辑，不做 A 目录补号检测",
    )
    parser.add_argument(
        "--monitor-interval",
        type=int,
        default=DEFAULT_CHECK_INTERVAL_SECONDS,
        help="巡检间隔秒数，默认 900 秒（15 分钟）",
    )
    parser.add_argument(
        "--register-batch-size",
        type=int,
        default=DEFAULT_REGISTER_BATCH_SIZE,
        help="巡检补号时每批并发注册数量",
    )
    parser.add_argument(
        "--register-openai-concurrency",
        type=int,
        default=DEFAULT_REGISTER_OPENAI_CONCURRENCY,
        help="注册流程最大并发数",
    )
    parser.add_argument(
        "--register-start-delay-seconds",
        type=float,
        default=DEFAULT_REGISTER_START_DELAY_SECONDS,
        help="启动下一个注册线程前的错峰等待秒数",
    )
    parser.add_argument(
        "--dingtalk-webhook",
        default=DEFAULT_DINGTALK_WEBHOOK,
        help="钉钉机器人 Webhook，留空则不发送提醒",
    )
    parser.add_argument(
        "--dingtalk-summary-interval",
        type=int,
        default=DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS,
        help="钉钉汇总发送间隔秒数，默认 10800 秒（3 小时）",
    )
    parser.add_argument(
        "--dingtalk-fallback-interval",
        type=int,
        default=DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
        help="兼容参数，当前未使用",
    )
    parser.add_argument(
        "--auto-continue-non-us",
        action="store_true",
        help="非 US 出口时自动继续，适合无人值守巡检",
    )
    parser.add_argument(
        "--test-cfmail",
        action="store_true",
        help="仅测试 cfmail 配置是否可创建邮箱并可轮询，不执行注册",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="执行轻量环境检查并输出结果",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="输出当前池子与运行配置状态，不执行注册/巡检",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="doctor/status 以 JSON 输出",
    )
    parser.add_argument(
        "--cfmail-fail-threshold",
        type=int,
        default=DEFAULT_CFMAIL_FAIL_THRESHOLD,
        help="兼容参数，当前未使用",
    )
    parser.add_argument(
        "--cfmail-cooldown-seconds",
        type=int,
        default=DEFAULT_CFMAIL_COOLDOWN_SECONDS,
        help="兼容参数，当前未使用",
    )
    args = parser.parse_args()

    # 保存 argparse 的默认值，用于判断命令行是否显式传参
    for action in parser._actions:
        if hasattr(action, "dest") and action.dest != "help":
            setattr(args, f"_default_{action.dest}", action.default)
    explicit_cli_dests = collect_explicit_cli_dests(parser)

    # 加载配置文件（命令行参数优先于配置文件）
    config = load_config_file(args.config)
    if config:
        logger.info(f"[信息] 已加载配置文件: {args.config}")
        apply_config_to_args(args, config, explicit_cli_dests=explicit_cli_dests)
    if "once" in explicit_cli_dests and "monitor" not in explicit_cli_dests and "monitor_once" not in explicit_cli_dests:
        args.register_only = True

    sleep_min = max(1, args.sleep_min)
    sleep_max = max(sleep_min, args.sleep_max)
    args.failure_sleep_seconds = max(0, args.failure_sleep_seconds)
    args.active_min_count = max(1, args.active_min_count)
    args.monitor_interval = max(1, args.monitor_interval)
    args.dingtalk_summary_interval = max(1, args.dingtalk_summary_interval)
    args.dingtalk_fallback_interval = max(0, args.dingtalk_fallback_interval)
    args.register_batch_size = max(1, args.register_batch_size)
    args.register_openai_concurrency = max(1, args.register_openai_concurrency)
    args.register_start_delay_seconds = max(0.0, float(args.register_start_delay_seconds))
    args.cfmail_fail_threshold = max(1, args.cfmail_fail_threshold)
    args.cfmail_cooldown_seconds = max(0, args.cfmail_cooldown_seconds)
    args.roxy_port = max(1, int(args.roxy_port or DEFAULT_ROXY_PORT))
    args.roxy_workspace_id = max(0, int(args.roxy_workspace_id or 0))
    args.registration_engine = str(args.registration_engine or DEFAULT_REGISTRATION_ENGINE).strip().lower() or DEFAULT_REGISTRATION_ENGINE
    args.browser_backend = str(args.browser_backend or DEFAULT_BROWSER_BACKEND).strip().lower() or DEFAULT_BROWSER_BACKEND
    args.browser_core_version = str(args.browser_core_version or DEFAULT_BROWSER_CORE_VERSION).strip() or DEFAULT_BROWSER_CORE_VERSION
    args.browser_os = str(args.browser_os or DEFAULT_BROWSER_OS).strip() or DEFAULT_BROWSER_OS
    args.roxy_token = str(args.roxy_token or DEFAULT_ROXY_TOKEN).strip()
    try:
        args.mail_providers = _parse_mail_providers(
            getattr(args, "mail_providers", ""),
            args.mail_provider,
        )
    except ValueError as exc:
        parser.error(str(exc))
    args.mail_provider = args.mail_providers[0]
    apply_low_memory_tuning(args)
    args.cfmail_profile = str(args.cfmail_profile or "auto").strip() or "auto"
    args.cfmail_profile_name = (
        str(args.cfmail_profile_name or "custom").strip() or "custom"
    )
    args.cfmail_config = (
        str(args.cfmail_config or DEFAULT_CFMAIL_CONFIG_PATH).strip()
        or DEFAULT_CFMAIL_CONFIG_PATH
    )

    has_cfmail_override = any(
        [
            args.cfmail_worker_domain,
            args.cfmail_email_domain,
            args.cfmail_admin_password,
        ]
    )
    if has_cfmail_override and not all(
        [
            args.cfmail_worker_domain,
            args.cfmail_email_domain,
            args.cfmail_admin_password,
        ]
    ):
        parser.error(
            "--cfmail-worker-domain / --cfmail-email-domain / --cfmail-admin-password 需要同时提供"
        )

    if has_cfmail_override:
        configured_cfmail_accounts = [
            CfmailAccount(
                name=args.cfmail_profile_name,
                worker_domain=_normalize_host(args.cfmail_worker_domain),
                email_domain=_normalize_host(args.cfmail_email_domain),
                admin_password=str(args.cfmail_admin_password or "").strip(),
            )
        ]
    else:
        configured_cfmail_accounts = _build_cfmail_accounts(
            _load_cfmail_accounts_from_file(args.cfmail_config) or DEFAULT_CFMAIL_ACCOUNTS
        )

    configure_cfmail_runtime(
        accounts=configured_cfmail_accounts,
        profile_mode=args.cfmail_profile,
        config_path=args.cfmail_config,
        hot_reload_enabled=not has_cfmail_override,
        fail_threshold=args.cfmail_fail_threshold,
        cooldown_seconds=args.cfmail_cooldown_seconds,
    )
    configure_browser_runtime(
        BrowserRuntimeConfig(
            registration_engine=args.registration_engine,
            backend=args.browser_backend,
            roxy_port=args.roxy_port,
            roxy_token=args.roxy_token,
            roxy_workspace_id=args.roxy_workspace_id,
            core_version=args.browser_core_version,
            os_name=args.browser_os,
            keep_profile_for_oauth=args.browser_keep_profile_for_oauth,
            screenshots_enabled=args.browser_screenshots_enabled,
            asset_cache_enabled=args.browser_asset_cache_enabled,
        )
    )

    inspection_mode = bool(args.doctor or args.status)
    selected_mail_providers = list(getattr(args, "mail_providers", []) or [args.mail_provider])
    selected_mail_provider_text = ",".join(selected_mail_providers)

    if (
        not inspection_mode
        and "cfmail" in selected_mail_providers
        and not get_cfmail_accounts()
    ):
        parser.error(
            "未配置可用的 cfmail 邮箱，请先在 cfmail 配置文件中添加，或通过 --cfmail-worker-domain 等参数临时指定"
        )

    if (
        not inspection_mode
        and "cfmail" in selected_mail_providers
        and args.cfmail_profile.lower() != "auto"
        and not _select_cfmail_account(args.cfmail_profile)
    ):
        parser.error(
            f"--cfmail-profile 指定的配置不存在：{args.cfmail_profile}；当前可用配置: {_cfmail_account_names()}"
        )

    if inspection_mode:
        doctor_report = collect_doctor_report(args) if args.doctor else None
        status_snapshot = build_status_snapshot(args) if args.status else None

        if args.json and doctor_report and status_snapshot:
            payload = {
                "doctor": {
                    "checked_at": doctor_report.checked_at,
                    "error_count": doctor_report.error_count,
                    "warn_count": doctor_report.warn_count,
                    "checks": [
                        {
                            "name": item.name,
                            "status": item.status,
                            "summary": item.summary,
                            "detail": item.detail,
                        }
                        for item in doctor_report.checks
                    ],
                },
                "status": status_snapshot,
            }
            print(json.dumps(payload, ensure_ascii=False, indent=2))
        else:
            if doctor_report:
                print_doctor_report(doctor_report, output_json=args.json)
            if doctor_report and status_snapshot and not args.json:
                print("")
            if status_snapshot:
                print_status_snapshot(status_snapshot, output_json=args.json)

        if doctor_report:
            sys.exit(1 if doctor_report.error_count > 0 else 0)
        return

    if args.test_cfmail:
        ok = run_cfmail_self_test(
            get_cfmail_accounts(),
            proxy=args.proxy,
            profile_name=args.cfmail_profile,
        )
        sys.exit(0 if ok else 1)

    # 默认行为：
    # - 直接执行脚本：跑一轮 A 目录补号检测（monitor_once）
    # - --monitor：持续巡检 A 目录
    # - --register-only：跳过巡检，直接进入注册模式
    run_single_monitor = not args.register_only and not args.monitor

    if args.monitor or args.monitor_once or run_single_monitor:
        if args.auto_continue_non_us or not sys.stdin.isatty():
            builtins.yasal_bypass_ip_choice = True

        if run_single_monitor and not args.monitor and not args.monitor_once:
            args.monitor_once = True

        cfmail_desc = ""
        if "cfmail" in selected_mail_providers:
            cfmail_desc = (
                f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，"
                f"选择={args.cfmail_profile}"
            )
        log_info(
            f"巡检模式启动：A目录={args.active_token_dir}，A阈值={args.active_min_count}，巡检间隔={args.monitor_interval}秒，注册并发={args.register_openai_concurrency}，批次={args.register_batch_size}，错峰={args.register_start_delay_seconds:.1f}秒，钉钉汇总间隔={args.dingtalk_summary_interval}秒，注册引擎={args.registration_engine}，邮箱服务={selected_mail_provider_text}{cfmail_desc}"
        )
        run_monitor_loop(
            args,
            run_with_fallback,
            _reload_cfmail_accounts_if_needed,
        )
        return

    if args.auto_continue_non_us:
        builtins.yasal_bypass_ip_choice = True

    startup_message = (
        f"[信息] 脚本启动：注册并发上限={args.register_openai_concurrency}，错峰={args.register_start_delay_seconds:.1f}秒，邮箱服务={selected_mail_provider_text}，注册引擎={args.registration_engine}，Token目录={args.token_dir}"
    )
    if "cfmail" in selected_mail_providers:
        startup_message += (
            f"，cfmail配置文件={args.cfmail_config}，cfmail配置={_cfmail_account_names()}，"
            f"选择={args.cfmail_profile}"
        )
    logger.info(startup_message)

    if (
        len(selected_mail_providers) == 1
        and selected_mail_providers[0] == "cfmail"
        and args.cfmail_profile.lower() == "auto"
        and _run_cfmail_profile_processes(
            args,
            sleep_min=sleep_min,
            sleep_max=sleep_max,
        )
    ):
        return

    worker_count = (
        1
        if len(selected_mail_providers) == 1 and selected_mail_providers[0] == "cfmail"
        else max(min(3, args.register_openai_concurrency), len(selected_mail_providers))
    )
    providers_list = [
        selected_mail_providers[index % len(selected_mail_providers)]
        for index in range(worker_count)
    ]
    threads = []

    for i in range(1, worker_count + 1):
        provider_key = providers_list[i - 1]
        t = threading.Thread(
            target=worker,
            args=(
                i,
                args.proxy,
                args.once,
                sleep_min,
                sleep_max,
                args.failure_sleep_seconds,
                provider_key,
                args.mailtm_api_base,
                args.token_dir,
                run_with_fallback,
                _reload_cfmail_accounts_if_needed,
                args.dingtalk_webhook,
                args.dingtalk_fallback_interval,
            ),
        )
        t.daemon = True
        t.start()
        threads.append(t)
        if args.register_start_delay_seconds > 0 and i < worker_count:
            time.sleep(args.register_start_delay_seconds)

    try:
        while True:
            time.sleep(1)
            if not any(t.is_alive() for t in threads):
                logger.info("\n[信息] 所有线程已执行完成，任务结束")
                break
    except KeyboardInterrupt:
        logger.info("\n[信息] 收到中断信号，准备退出")


if __name__ == "__main__":
    main()
