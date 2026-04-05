"""Registration workers and monitor loop orchestration."""

from __future__ import annotations

import builtins
import os
import random
import threading
import time
from datetime import datetime
from typing import Any, Optional

from ..notifications import build_monitor_summary_message, send_dingtalk_alert
from .common import (
    DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
    MonitorCycleResult,
    RegisterRunner,
    ReloadCfmailHook,
    SHORTAGE_FAIL_RETRY_SECONDS,
    SHORTAGE_FAST_RETRY_SECONDS,
    count_json_files,
    log_error,
    log_info,
    log_warn,
    persist_registration_result,
)


def _normalize_provider_list(provider_keys: Any) -> list[str]:
    if isinstance(provider_keys, str):
        value = str(provider_keys or "").strip()
        return [value] if value else []
    if isinstance(provider_keys, (list, tuple, set)):
        normalized = []
        for item in provider_keys:
            value = str(item or "").strip()
            if value:
                normalized.append(value)
        return normalized
    value = str(provider_keys or "").strip()
    return [value] if value else []


def register_single_account(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
    token_dir: str,
    register_runner: RegisterRunner,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> bool:
    try:
        result, _used_provider = register_runner(
            proxy,
            provider_key,
            thread_id,
            mailtm_base,
            dingtalk_webhook=dingtalk_webhook,
            dingtalk_fallback_interval_seconds=dingtalk_fallback_interval_seconds,
        )
        if not result:
            log_warn(f"补号任务 #{thread_id} 失败")
            return False

        token_json, password = result
        persist_registration_result(token_json, password, thread_id, token_dir)
        return True
    except Exception as exc:
        log_error(f"补号任务 #{thread_id} 异常: {exc}")
        return False


def register_accounts(
    target_count: int,
    proxy: Optional[str],
    provider_keys: Any,
    mailtm_base: str,
    token_dir: str,
    batch_size: int,
    register_openai_concurrency: int,
    register_start_delay_seconds: float,
    auto_continue_non_us: bool,
    register_runner: RegisterRunner,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> int:
    if target_count <= 0:
        return 0

    normalized_providers = _normalize_provider_list(provider_keys)
    if not normalized_providers:
        normalized_providers = [""]
    if len(normalized_providers) > 1:
        min_parallelism = min(len(normalized_providers), max(1, target_count))
        batch_size = max(batch_size, min_parallelism)
        register_openai_concurrency = max(register_openai_concurrency, min_parallelism)

    if auto_continue_non_us and getattr(builtins, "yasal_bypass_ip_choice", None) is None:
        builtins.yasal_bypass_ip_choice = True

    success_count = 0
    attempts = 0
    batch_size = max(1, batch_size)
    register_openai_concurrency = max(1, register_openai_concurrency)
    register_start_delay_seconds = max(0.0, float(register_start_delay_seconds))
    max_attempts = max(target_count * 4, target_count + batch_size)

    while success_count < target_count and attempts < max_attempts:
        current_batch_size = min(
            batch_size,
            register_openai_concurrency,
            target_count - success_count,
            max_attempts - attempts,
        )
        batch_success_count = 0
        batch_results_lock = threading.Lock()
        threads: list[threading.Thread] = []

        for index in range(current_batch_size):
            current_thread_id = attempts + index + 1
            current_provider = normalized_providers[(attempts + index) % len(normalized_providers)]

            def _task(tid: int = current_thread_id, provider: str = current_provider) -> None:
                nonlocal batch_success_count
                is_success = register_single_account(
                    proxy,
                    provider,
                    tid,
                    mailtm_base,
                    token_dir,
                    register_runner,
                    dingtalk_webhook,
                    dingtalk_fallback_interval_seconds,
                )
                if is_success:
                    with batch_results_lock:
                        batch_success_count += 1

            thread = threading.Thread(target=_task, daemon=True)
            thread.start()
            threads.append(thread)
            if register_start_delay_seconds > 0 and index + 1 < current_batch_size:
                time.sleep(register_start_delay_seconds)

        for thread in threads:
            thread.join()

        attempts += current_batch_size
        batch_success = batch_success_count
        success_count += batch_success
        log_info(f"补号批次完成：本批成功 {batch_success} 个，累计成功 {success_count}/{target_count}")

        if batch_success == 0 and success_count < target_count:
            time.sleep(10)

    if success_count < target_count:
        log_warn(f"目标补号 {target_count} 个，实际仅补充成功 {success_count} 个")

    return success_count


def run_monitor_cycle(args: Any, register_runner: RegisterRunner) -> MonitorCycleResult:
    os.makedirs(args.active_token_dir, exist_ok=True)

    log_info("========== 开始执行 A 目录补号检测 ==========")
    log_info("当前已禁用删号、额度查询、B->A 搬运、B 目录补号；本轮仅维护 A 目录")

    active_count = count_json_files(args.active_token_dir)
    active_shortage = max(args.active_min_count - active_count, 0)
    register_target = active_shortage
    log_info(
        f"当前库存统计：A={active_count}/{args.active_min_count}（缺 {active_shortage}）；B 目录已忽略"
    )

    replenished_count = 0
    replenished_to_active = 0

    if register_target > 0:
        log_warn(
            f"检测到 A 库存不足：A={active_count}/{args.active_min_count}，准备补号 {register_target} 个"
        )
        log_info(f"A 目录存在缺口，直接补号到 A：计划补 {active_shortage} 个到 {args.active_token_dir}")
        replenished_to_active = register_accounts(
            active_shortage,
            args.proxy,
            getattr(args, "mail_providers", None) or args.mail_provider,
            args.mailtm_api_base,
            args.active_token_dir,
            args.register_batch_size,
            args.register_openai_concurrency,
            args.register_start_delay_seconds,
            args.auto_continue_non_us,
            register_runner,
            args.dingtalk_webhook,
            args.dingtalk_fallback_interval,
        )
        replenished_count += replenished_to_active
        log_info(
            f"A 补号完成：总计划补 {register_target} 个，"
            f"A 补号成功 {replenished_to_active} 个"
        )
    else:
        log_info(
            f"A 已达标：A={active_count}/{args.active_min_count}，本轮不补号"
        )

    final_active_count = count_json_files(args.active_token_dir)
    final_active_shortage = max(args.active_min_count - final_active_count, 0)

    log_info(
        f"本轮汇总：删 A=0，删 B=0，B→A=0，注册成功={replenished_count}"
    )
    log_info(
        f"检测结束：A={final_active_count}/{args.active_min_count}（缺 {final_active_shortage}），B 目录已忽略，补号={replenished_count}"
    )
    log_info("========== A 目录补号检测执行完成 ==========")
    return MonitorCycleResult(
        completed_at=datetime.now(),
        active_count=final_active_count,
        pool_count=0,
        active_target=args.active_min_count,
        pool_target=0,
        active_shortage=final_active_shortage,
        pool_shortage=0,
        attempted_replenish=register_target > 0,
        register_target=register_target,
        replenished_count=replenished_count,
        deleted_count=0,
        active_deleted_count=0,
        pool_deleted_count=0,
        moved_to_active_count=0,
        active_check_failed=0,
        pool_check_failed=0,
    )


def worker(
    thread_id: int,
    proxy: Optional[str],
    once: bool,
    sleep_min: int,
    sleep_max: int,
    failure_sleep_seconds: int,
    provider_key: str,
    mailtm_base: str,
    token_dir: str,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> None:
    count = 0
    while True:
        if provider_key == "cfmail" and reload_cfmail_accounts:
            reload_cfmail_accounts()
        count += 1
        log_info(f"[线程 {thread_id}] 开始第 {count} 次任务（邮箱服务: {provider_key}）")

        try:
            result, used_provider = register_runner(
                proxy,
                provider_key,
                thread_id,
                mailtm_base,
                dingtalk_webhook=dingtalk_webhook,
                dingtalk_fallback_interval_seconds=dingtalk_fallback_interval_seconds,
            )

            is_success = False
            if result:
                token_json, password = result
                file_name, _raw_email = persist_registration_result(
                    token_json,
                    password,
                    thread_id,
                    token_dir,
                )
                log_info(
                    f"[线程 {thread_id}] 账号信息已追加到 output/accounts.txt，"
                    f"Token 已保存到: {file_name}（邮箱服务: {used_provider}）"
                )
                is_success = True
            else:
                log_warn(f"[线程 {thread_id}] 本轮任务未成功")
        except Exception as exc:
            log_error(f"[线程 {thread_id}] 发生未捕获异常: {exc}")
            is_success = False

        if once:
            break

        wait_time = random.randint(sleep_min, sleep_max)
        if not is_success:
            log_info(f"[线程 {thread_id}] 本轮失败，额外等待 {failure_sleep_seconds} 秒后重试")
            wait_time += max(0, failure_sleep_seconds)

        time.sleep(wait_time)


def run_monitor_loop(
    args: Any,
    register_runner: RegisterRunner,
    reload_cfmail_accounts: Optional[ReloadCfmailHook] = None,
) -> None:
    pending_results: list[MonitorCycleResult] = []
    summary_started_at = time.time()
    while True:
        selected_providers = _normalize_provider_list(
            getattr(args, "mail_providers", None) or args.mail_provider
        )
        if "cfmail" in selected_providers and reload_cfmail_accounts:
            reload_cfmail_accounts()
        cycle_started_at = time.time()
        try:
            cycle_result = run_monitor_cycle(args, register_runner)
            pending_results.append(cycle_result)
        except Exception as exc:
            log_error(f"检测循环异常: {exc}")
            cycle_result = None

        should_send_summary = False
        now_ts = time.time()
        if pending_results:
            if args.monitor_once:
                should_send_summary = True
            elif now_ts - summary_started_at >= args.dingtalk_summary_interval:
                should_send_summary = True

        if should_send_summary:
            summary_message = build_monitor_summary_message(pending_results)
            if summary_message:
                send_dingtalk_alert(args.dingtalk_webhook, summary_message)
                log_info(f"已发送钉钉汇总通知，共汇总 {len(pending_results)} 轮检测结果")
            pending_results = []
            summary_started_at = now_ts

        if args.monitor_once:
            break

        elapsed_seconds = int(time.time() - cycle_started_at)
        has_shortage = cycle_result is not None and cycle_result.active_shortage > 0
        if has_shortage:
            attempted_but_failed = cycle_result.attempted_replenish and cycle_result.replenished_count == 0
            if attempted_but_failed:
                target_interval = max(SHORTAGE_FAIL_RETRY_SECONDS, args.monitor_interval // 3)
            else:
                target_interval = max(SHORTAGE_FAST_RETRY_SECONDS, args.monitor_interval // 5)
            sleep_seconds = max(1, target_interval - elapsed_seconds)
            log_info(
                f"检测到 A 库存缺口（缺 {cycle_result.active_shortage}），缩短等待间隔，"
                f"{sleep_seconds} 秒后进入下一轮检测"
            )
        else:
            sleep_seconds = max(1, args.monitor_interval - elapsed_seconds)
            log_info(f"等待 {sleep_seconds} 秒后进入下一轮检测")
        time.sleep(sleep_seconds)


__all__ = [
    "register_accounts",
    "register_single_account",
    "run_monitor_cycle",
    "run_monitor_loop",
    "worker",
]
