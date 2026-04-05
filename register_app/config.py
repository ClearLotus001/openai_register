# -*- coding: utf-8 -*-
"""配置常量、配置文件加载、低内存自动调优与 CLI 辅助函数。

本模块集中管理 OpenAI 注册脚本的全部默认参数与配置逻辑，
使其余模块可以按需导入而不必关心具体的配置细节。
"""
import argparse
import ctypes
import json
import logging
import os
from typing import Dict

logger = logging.getLogger("openai_register")

# ---------------------------------------------------------------------------
# 脚本所在目录，作为默认路径的基准
# ---------------------------------------------------------------------------
_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ---------------------------------------------------------------------------
# 默认常量
# ---------------------------------------------------------------------------
DEFAULT_ACTIVE_TOKEN_DIR = os.path.join(_SCRIPT_DIR, "auths")
DEFAULT_TOKEN_OUTPUT_DIR = os.path.join(_SCRIPT_DIR, "auths_pool")
DEFAULT_MIN_ACTIVE_COUNT = 20
DEFAULT_CHECK_INTERVAL_SECONDS = 900
DEFAULT_DINGTALK_SUMMARY_INTERVAL_SECONDS = 10800
DEFAULT_REGISTER_BATCH_SIZE = 1
DEFAULT_REGISTER_OPENAI_CONCURRENCY = 1
DEFAULT_REGISTER_START_DELAY_SECONDS = 8.0
DEFAULT_REGISTER_FAILURE_EXTRA_SLEEP_SECONDS = 20
DEFAULT_DINGTALK_WEBHOOK = ""
DEFAULT_CFMAIL_FALLBACK_PROVIDER = "tempmaillol"
DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS = 900
CREATE_ACCOUNT_MAX_ATTEMPTS = 2
CREATE_ACCOUNT_RETRY_DELAY_SECONDS = 2
DEFAULT_REGISTRATION_ENGINE = "http"
DEFAULT_BROWSER_BACKEND = "roxy"
DEFAULT_ROXY_PORT = 50000
DEFAULT_ROXY_TOKEN = ""
DEFAULT_ROXY_WORKSPACE_ID = 0
DEFAULT_BROWSER_CORE_VERSION = "145"
DEFAULT_BROWSER_OS = "macOS"
DEFAULT_BROWSER_KEEP_PROFILE_FOR_OAUTH = True
DEFAULT_BROWSER_SCREENSHOTS_ENABLED = True
DEFAULT_BROWSER_ASSET_CACHE_ENABLED = False
LOW_MEMORY_SOFT_LIMIT_MB = 2560
LOW_MEMORY_HARD_LIMIT_MB = 1536

DEFAULT_CONFIG_PATH = os.path.join(_SCRIPT_DIR, "monitor_config.json")

# ---------------------------------------------------------------------------
# 配置文件中的 key 到 argparse dest 的映射
# ---------------------------------------------------------------------------
_CONFIG_KEY_MAP: Dict[str, str] = {
    "proxy": "proxy",
    "mail_provider": "mail_provider",
    "cfmail_profile": "cfmail_profile",
    "cfmail_config": "cfmail_config",
    "cfmail_worker_domain": "cfmail_worker_domain",
    "cfmail_email_domain": "cfmail_email_domain",
    "cfmail_admin_password": "cfmail_admin_password",
    "cfmail_profile_name": "cfmail_profile_name",
    "mailtm_api_base": "mailtm_api_base",
    "token_dir": "token_dir",
    "active_token_dir": "active_token_dir",
    "active_min_count": "active_min_count",
    "monitor_interval": "monitor_interval",
    "register_batch_size": "register_batch_size",
    "register_openai_concurrency": "register_openai_concurrency",
    "register_start_delay_seconds": "register_start_delay_seconds",
    "dingtalk_webhook": "dingtalk_webhook",
    "dingtalk_summary_interval": "dingtalk_summary_interval",
    "dingtalk_fallback_interval": "dingtalk_fallback_interval",
    "sleep_min": "sleep_min",
    "sleep_max": "sleep_max",
    "failure_sleep_seconds": "failure_sleep_seconds",
    "cfmail_fail_threshold": "cfmail_fail_threshold",
    "cfmail_cooldown_seconds": "cfmail_cooldown_seconds",
    "registration_engine": "registration_engine",
    "browser_backend": "browser_backend",
    "roxy_port": "roxy_port",
    "roxy_token": "roxy_token",
    "roxy_workspace_id": "roxy_workspace_id",
    "browser_core_version": "browser_core_version",
    "browser_os": "browser_os",
    "browser_keep_profile_for_oauth": "browser_keep_profile_for_oauth",
    "browser_screenshots_enabled": "browser_screenshots_enabled",
    "browser_asset_cache_enabled": "browser_asset_cache_enabled",
}

# 布尔型参数（配置文件里 true/false）
_CONFIG_BOOL_KEYS = {
    "monitor",
    "monitor_once",
    "register_only",
    "auto_continue_non_us",
    "once",
    "test_cfmail",
}


# ---------------------------------------------------------------------------
# 配置文件加载
# ---------------------------------------------------------------------------


def load_config_file(config_path: str) -> dict:
    """加载 JSON 配置文件，返回配置字典。文件不存在则返回空字典。"""
    if not config_path or not os.path.isfile(config_path):
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        # 过滤掉以 _ 开头的注释字段
        return {k: v for k, v in data.items() if not k.startswith("_")}
    except Exception as exc:
        logger.warning(f"[警告] 读取配置文件 {config_path} 失败: {exc}")
        return {}


def apply_config_to_args(args: argparse.Namespace, config: dict) -> None:
    """将配置文件中的值填入 args，仅当命令行未显式指定时生效。"""
    for config_key, arg_dest in _CONFIG_KEY_MAP.items():
        if config_key not in config:
            continue
        # 仅当 argparse 使用了默认值时才覆盖（命令行显式指定的优先）
        current_val = getattr(args, arg_dest, None)
        default_val = getattr(args, f"_default_{arg_dest}", current_val)
        if current_val == default_val:
            setattr(args, arg_dest, config[config_key])

    for bool_key in _CONFIG_BOOL_KEYS:
        if bool_key not in config:
            continue
        current_val = getattr(args, bool_key, False)
        if not current_val:
            setattr(args, bool_key, bool(config[bool_key]))


# ---------------------------------------------------------------------------
# 内存检测与低内存自动调优
# ---------------------------------------------------------------------------


def detect_total_memory_mb() -> int:
    """检测系统总物理内存（MB），无法检测时返回 0。"""
    try:
        if os.path.exists("/proc/meminfo"):
            with open("/proc/meminfo", "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith("MemTotal:"):
                        parts = line.split()
                        if len(parts) >= 2:
                            return max(0, int(parts[1]) // 1024)
    except Exception:
        pass

    try:
        class MEMORYSTATUSEX(ctypes.Structure):
            _fields_ = [
                ("dwLength", ctypes.c_ulong),
                ("dwMemoryLoad", ctypes.c_ulong),
                ("ullTotalPhys", ctypes.c_ulonglong),
                ("ullAvailPhys", ctypes.c_ulonglong),
                ("ullTotalPageFile", ctypes.c_ulonglong),
                ("ullAvailPageFile", ctypes.c_ulonglong),
                ("ullTotalVirtual", ctypes.c_ulonglong),
                ("ullAvailVirtual", ctypes.c_ulonglong),
                ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
            ]

        status = MEMORYSTATUSEX()
        status.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
        if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
            return max(0, int(status.ullTotalPhys // (1024 * 1024)))
    except Exception:
        pass

    return 0


def apply_low_memory_tuning(args: argparse.Namespace) -> None:
    """根据系统内存自动收敛并发参数（低内存环境下降低资源消耗）。"""
    total_memory_mb = detect_total_memory_mb()
    if total_memory_mb <= 0:
        return

    args.detected_total_memory_mb = total_memory_mb
    if total_memory_mb <= LOW_MEMORY_HARD_LIMIT_MB:
        max_register_concurrency = 1
        max_register_batch_size = 1
        profile_name = "hard"
    elif total_memory_mb <= LOW_MEMORY_SOFT_LIMIT_MB:
        max_register_concurrency = 2
        max_register_batch_size = 2
        profile_name = "soft"
    else:
        return

    original_values = (
        args.register_openai_concurrency,
        args.register_batch_size,
    )
    args.register_openai_concurrency = min(
        args.register_openai_concurrency,
        max_register_concurrency,
    )
    args.register_batch_size = min(
        args.register_batch_size,
        max_register_batch_size,
    )
    tuned_values = (
        args.register_openai_concurrency,
        args.register_batch_size,
    )
    if tuned_values != original_values:
        logger.info(
            "[信息] 检测到低内存环境（总内存约 %s MB，profile=%s），"
            "已自动收敛并发：register_openai_concurrency=%s，register_batch_size=%s",
            total_memory_mb,
            profile_name,
            args.register_openai_concurrency,
            args.register_batch_size,
        )
