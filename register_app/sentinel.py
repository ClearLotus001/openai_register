# -*- coding: utf-8 -*-
"""Sentinel POW 求解、随机浏览器指纹池与 sentinel 请求相关逻辑。

本模块封装了 OpenAI Sentinel 防机器人机制所需的全部功能：
- 随机浏览器指纹池（降低批量注册被风控识别的风险）
- Sentinel POW（Proof of Work）求解
- Sentinel 请求头的获取
"""
import base64
import hashlib
import json
import logging
import random
import time
import urllib.parse
import uuid
from datetime import datetime
from typing import Any, List, Sequence

from curl_cffi import requests
from .sentinel_sidecar import (
    generate_sentinel_requirements_token_via_sidecar,
    run_sentinel_vm_sidecar,
)

logger = logging.getLogger("openai_register")

# ---------------------------------------------------------------------------
# Sentinel 常量
# ---------------------------------------------------------------------------
SENTINEL_VERSION = "20260219f9f6"
SENTINEL_FRAME_URL = (
    f"https://sentinel.openai.com/backend-api/sentinel/frame.html?sv={SENTINEL_VERSION}"
)
SENTINEL_SDK_URL = f"https://sentinel.openai.com/sentinel/{SENTINEL_VERSION}/sdk.js"
SENTINEL_CHATGPT_FRAME_URL = (
    f"https://chatgpt.com/backend-api/sentinel/frame.html?sv={SENTINEL_VERSION}"
)
SENTINEL_CHATGPT_SDK_URL = f"https://chatgpt.com/sentinel/{SENTINEL_VERSION}/sdk.js"
SENTINEL_DOCUMENT_KEYS = ("visibilityState", "readyState", "documentURI", "location")
SENTINEL_WINDOW_KEYS = ("location", "document", "navigator", "origin", "window")
SENTINEL_SCRIPT_SOURCES = (
    SENTINEL_SDK_URL,
    SENTINEL_FRAME_URL,
    SENTINEL_CHATGPT_SDK_URL,
    SENTINEL_CHATGPT_FRAME_URL,
)
SENTINEL_POW_PREFIX = "gAAAAAB"
SENTINEL_REQUIREMENTS_PREFIX = "gAAAAAC"
SENTINEL_REQUIREMENTS_ERROR_PREFIX = "wQ8Lk5FbGpA2NcR9dShT6gYjU7VxZ4D"
SENTINEL_POW_SUFFIX = "~S"
SENTINEL_POW_MAX_ATTEMPTS = 500000
SENTINEL_POW_TIMEOUT_SECONDS = 20
SENTINEL_DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36"
)
SENTINEL_DEFAULT_JS_HEAP_SIZE_LIMIT = 4294705152
SENTINEL_DEFAULT_SCREEN_SUM = 3000
SENTINEL_DEFAULT_LANGUAGE = "en-US"
SENTINEL_DEFAULT_LANGUAGES = "en-US,en"
SENTINEL_DEFAULT_HARDWARE_CONCURRENCY = 8
SENTINEL_MINUS_SIGN = "\u2212"
SENTINEL_WEEKDAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
SENTINEL_MONTH_NAMES = (
    "Jan",
    "Feb",
    "Mar",
    "Apr",
    "May",
    "Jun",
    "Jul",
    "Aug",
    "Sep",
    "Oct",
    "Nov",
    "Dec",
)

# ---------------------------------------------------------------------------
# 随机指纹池：降低批量注册被风控识别的风险
# ---------------------------------------------------------------------------
IMPERSONATE_POOL = (
    "chrome",
    "chrome110",
    "chrome116",
    "chrome120",
    "chrome123",
    "chrome124",
    "chrome131",
)

CHROME_UA_POOL = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
)

# 常见屏幕分辨率的 width + height 之和
SCREEN_SUM_POOL = (2160, 2560, 3000, 3360, 3840, 4320)

# 常见硬件并发数
HARDWARE_CONCURRENCY_POOL = (2, 4, 6, 8, 12, 16)

# JS 堆内存限制常见值
JS_HEAP_SIZE_POOL = (2147483648, 4294705152, 4294967296)

# 浏览器平台标识
PLATFORM_POOL = (
    ("Win32", "Google Inc."),
    ("MacIntel", "Google Inc."),
    ("Linux x86_64", "Google Inc."),
)

# 语言配置
LANGUAGE_POOL = (
    ("en-US", "en-US,en"),
    ("en-GB", "en-GB,en"),
    ("en-US", "en-US,en,zh-CN"),
)


# ---------------------------------------------------------------------------
# 随机指纹选取
# ---------------------------------------------------------------------------


def random_impersonate() -> str:
    """从指纹池中随机选取一个 curl_cffi impersonate 标识。"""
    return random.choice(IMPERSONATE_POOL)


def random_user_agent() -> str:
    """从 UA 池中随机选取一个 User-Agent 字符串。"""
    return random.choice(CHROME_UA_POOL)


def build_sentinel_requirements_token() -> str:
    """构造更接近官方 SDK 的 requirements token。"""
    return _generate_sentinel_requirements_token()


# ---------------------------------------------------------------------------
# Sentinel POW 内部工具函数
# ---------------------------------------------------------------------------


def _sentinel_js_now_string() -> str:
    """生成 JavaScript 风格的当前时间字符串。"""
    now = datetime.now().astimezone()
    offset = now.strftime("%z")
    if len(offset) == 5:
        offset = f"{offset[:3]}:{offset[3:]}"
    return (
        f"{SENTINEL_WEEKDAY_NAMES[now.weekday()]} "
        f"{SENTINEL_MONTH_NAMES[now.month - 1]} "
        f"{now.day:02d} {now.year:04d} "
        f"{now.hour:02d}:{now.minute:02d}:{now.second:02d} "
        f"GMT{offset or '+00:00'}"
    )


def _sentinel_b64_json(value: Any) -> str:
    """将值编码为 JSON 后再进行 Base64 编码。"""
    raw = json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _sentinel_hash_hex(value: str) -> str:
    """FNV-1a 变体哈希，返回 8 位十六进制字符串。"""
    hashed = 2166136261
    for ch in str(value or ""):
        hashed ^= ord(ch)
        hashed = (hashed * 16777619) & 0xFFFFFFFF
    hashed ^= hashed >> 16
    hashed = (hashed * 2246822507) & 0xFFFFFFFF
    hashed ^= hashed >> 13
    hashed = (hashed * 3266489909) & 0xFFFFFFFF
    hashed ^= hashed >> 16
    return f"{hashed & 0xFFFFFFFF:08x}"


def _sentinel_query_keys_signature() -> str:
    """提取 Sentinel frame URL 中的查询参数键名签名。"""
    return ",".join(
        urllib.parse.parse_qs(
            urllib.parse.urlparse(SENTINEL_FRAME_URL).query,
            keep_blank_values=True,
        ).keys()
    )


def _sentinel_random_choice(values: Sequence[str], default: str = "") -> str:
    """从序列中随机选取一个值，序列为空时返回默认值。"""
    if not values:
        return default
    return random.choice(values)


def _build_sentinel_pow_fingerprint() -> List[Any]:
    """构建一组随机化的 Sentinel POW 指纹参数。

    每次调用随机选取一组完整指纹参数，降低批量注册时的指纹关联性。
    """
    platform_vendor = random.choice(PLATFORM_POOL)
    platform_str, vendor_str = platform_vendor
    language_pair = random.choice(LANGUAGE_POOL)
    lang, langs = language_pair
    hw_concurrency = random.choice(HARDWARE_CONCURRENCY_POOL)
    screen_sum = random.choice(SCREEN_SUM_POOL)
    heap_limit = random.choice(JS_HEAP_SIZE_POOL)
    ua = random_user_agent()

    navigator_values = {
        "vendor": vendor_str,
        "platform": platform_str,
        "languages": langs,
        "language": lang,
        "userAgent": ua,
        "hardwareConcurrency": str(hw_concurrency),
    }
    nav_key = _sentinel_random_choice(tuple(navigator_values.keys()), "userAgent")
    perf_now_ms = time.perf_counter() * 1000
    time_origin_ms = int(time.time() * 1000 - perf_now_ms)
    return [
        screen_sum,
        _sentinel_js_now_string(),
        heap_limit,
        random.random(),
        ua,
        _sentinel_random_choice(SENTINEL_SCRIPT_SOURCES, SENTINEL_SDK_URL),
        _sentinel_random_choice(SENTINEL_SCRIPT_SOURCES, SENTINEL_SDK_URL),
        lang,
        langs,
        random.random(),
        (
            f"{nav_key}{SENTINEL_MINUS_SIGN}"
            f"{navigator_values.get(nav_key, ua)}"
        ),
        _sentinel_random_choice(SENTINEL_DOCUMENT_KEYS, "visibilityState"),
        _sentinel_random_choice(SENTINEL_WINDOW_KEYS, "location"),
        perf_now_ms,
        str(uuid.uuid4()),
        _sentinel_query_keys_signature(),
        hw_concurrency,
        time_origin_ms,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]


def _build_sentinel_requirements_fingerprint(requirements_seed: str) -> List[Any]:
    """构建更贴近官方 SDK `initializeAndGatherData()` 的 requirements 指纹。"""
    language_pair = random.choice(LANGUAGE_POOL)
    lang, langs = language_pair
    hw_concurrency = random.choice(HARDWARE_CONCURRENCY_POOL)
    screen_sum = random.choice(SCREEN_SUM_POOL)
    heap_limit = random.choice(JS_HEAP_SIZE_POOL)
    ua = random_user_agent()
    nav_key = _sentinel_random_choice(
        ("userAgent", "language", "languages", "hardwareConcurrency", "platform"),
        "userAgent",
    )
    navigator_values = {
        "userAgent": ua,
        "language": lang,
        "languages": langs,
        "hardwareConcurrency": str(hw_concurrency),
        "platform": _sentinel_random_choice(("Win32", "MacIntel", "Linux x86_64"), "Win32"),
    }
    perf_now_ms = time.perf_counter() * 1000
    time_origin_ms = int(time.time() * 1000 - perf_now_ms)
    build_marker = _sentinel_random_choice(
        ("prod-sidecar", "prod-chatgpt", "prod-auth"),
        "prod-sidecar",
    )
    query_keys = "callbackUrl,screen_hint"
    return [
        screen_sum,
        _sentinel_js_now_string(),
        heap_limit,
        random.random(),
        ua,
        _sentinel_random_choice(SENTINEL_SCRIPT_SOURCES, SENTINEL_SDK_URL),
        build_marker,
        lang,
        langs,
        round((time.perf_counter() - (perf_now_ms / 1000)) * 1000),
        f"{nav_key}{SENTINEL_MINUS_SIGN}{navigator_values.get(nav_key, ua)}",
        _sentinel_random_choice(("visibilityState", "readyState", "documentURI", "location"), "location"),
        _sentinel_random_choice(("location", "document", "navigator", "origin", "window"), "location"),
        perf_now_ms,
        str(uuid.uuid4()),
        query_keys,
        hw_concurrency,
        time_origin_ms,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    ]


def _generate_sentinel_requirements_token() -> str:
    """生成 requirements token。"""
    requirements_seed = str(random.random())
    started_at = time.perf_counter()
    candidate = _build_sentinel_requirements_fingerprint(requirements_seed)
    for attempt in range(SENTINEL_POW_MAX_ATTEMPTS):
        candidate[3] = attempt
        candidate[9] = round((time.perf_counter() - started_at) * 1000)
        encoded = _sentinel_b64_json(candidate)
        if _sentinel_hash_hex(requirements_seed + encoded)[:1] <= "0":
            return f"{SENTINEL_REQUIREMENTS_PREFIX}{encoded}{SENTINEL_POW_SUFFIX}"
    return (
        SENTINEL_REQUIREMENTS_PREFIX
        + SENTINEL_REQUIREMENTS_ERROR_PREFIX
        + _sentinel_b64_json("e")
    )


# ---------------------------------------------------------------------------
# Sentinel POW 求解
# ---------------------------------------------------------------------------


def solve_sentinel_pow(*, seed: str, difficulty: str, thread_id: int) -> str:
    """求解 Sentinel Proof-of-Work 挑战。

    :param seed: 服务端下发的随机种子
    :param difficulty: 目标难度（十六进制前缀）
    :param thread_id: 当前线程标识（用于日志）
    :returns: 求解成功返回编码后的 POW 字符串，失败返回空字符串
    """
    seed_text = str(seed or "").strip()
    target = str(difficulty or "").strip().lower()
    if not seed_text or not target:
        return ""

    perf_counter = time.perf_counter
    hash_hex = _sentinel_hash_hex
    encode_candidate = _sentinel_b64_json
    started_at = perf_counter()
    candidate = _build_sentinel_pow_fingerprint()
    prefix_len = len(target)
    timeout = SENTINEL_POW_TIMEOUT_SECONDS

    for attempt in range(SENTINEL_POW_MAX_ATTEMPTS):
        elapsed = perf_counter() - started_at
        if elapsed >= timeout:
            elapsed_ms = round(elapsed * 1000)
            logger.error(
                f"[线程 {thread_id}] [错误] Sentinel POW 求解超时（{timeout}秒），难度={target}，"
                f"已尝试 {attempt + 1} 次，耗时 {elapsed_ms} ms"
            )
            return ""

        candidate[3] = attempt
        candidate[9] = round((perf_counter() - started_at) * 1000)
        encoded = encode_candidate(candidate)
        if hash_hex(seed_text + encoded)[:prefix_len] <= target:
            elapsed_ms = round((perf_counter() - started_at) * 1000)
            logger.info(
                f"[线程 {thread_id}] [信息] Sentinel POW 求解成功，难度={target}，"
                f"尝试 {attempt + 1} 次，耗时 {elapsed_ms} ms"
            )
            return f"{SENTINEL_POW_PREFIX}{encoded}{SENTINEL_POW_SUFFIX}"

    elapsed_ms = round((perf_counter() - started_at) * 1000)
    logger.error(
        f"[线程 {thread_id}] [错误] Sentinel POW 求解失败，难度={target}，"
        f"已尝试 {SENTINEL_POW_MAX_ATTEMPTS} 次，耗时 {elapsed_ms} ms"
    )
    return ""


# ---------------------------------------------------------------------------
# Sentinel 请求头获取
# ---------------------------------------------------------------------------


def request_sentinel_header(
    *,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    flow: str = "authorize_continue",
) -> str:
    """向 Sentinel 服务端请求并返回完整的 sentinel-token JSON 字符串。

    :param did: 设备标识（oai-did）
    :param proxies: 代理配置
    :param impersonate: curl_cffi impersonate 标识
    :param thread_id: 当前线程标识（用于日志）
    :param flow: Sentinel 流程名称
    :returns: 成功返回 JSON 字符串，失败返回空字符串
    """
    device_id = str(did or "").strip()
    if not device_id:
        logger.error(f"[线程 {thread_id}] [错误] 无法获取 Device ID，Sentinel 请求已跳过")
        return ""

    flow_name = str(flow or "authorize_continue").strip() or "authorize_continue"

    tokens = request_sentinel_tokens(
        did=device_id,
        proxies=proxies,
        impersonate=impersonate,
        thread_id=thread_id,
        flow=flow_name,
    )
    return str(tokens.get("header") or "").strip()


def request_sentinel_tokens(
    *,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    flow: str = "authorize_continue",
) -> dict:
    """请求 Sentinel token 相关产物。

    返回：
    - header: `OpenAI-Sentinel-Token` JSON 字符串
    - so_token: `OpenAI-Sentinel-SO-Token` JSON 字符串（若可得）
    - payload / proof / requirements_token / sidecar: 调试辅助字段
    """
    device_id = str(did or "").strip()
    if not device_id:
        logger.error(f"[线程 {thread_id}] [错误] 无法获取 Device ID，Sentinel 请求已跳过")
        return {}

    flow_name = str(flow or "authorize_continue").strip() or "authorize_continue"
    requirements_token = (
        generate_sentinel_requirements_token_via_sidecar(
            did=device_id,
            flow=flow_name,
            user_agent=random_user_agent(),
            script_sources=SENTINEL_SCRIPT_SOURCES,
        )
        or build_sentinel_requirements_token()
    )
    body = json.dumps(
        {"p": requirements_token, "id": device_id, "flow": flow_name},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    sentinel_payload = request_sentinel_payload(
        did=device_id,
        proxies=proxies,
        impersonate=impersonate,
        thread_id=thread_id,
        flow=flow_name,
        request_body=body,
    )
    if not sentinel_payload:
        fallback_body = json.dumps(
            {"p": "", "id": device_id, "flow": flow_name},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        sentinel_payload = request_sentinel_payload(
            did=device_id,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
            flow=flow_name,
            request_body=fallback_body,
        )
        if not sentinel_payload:
            return {}
        requirements_token = ""

    token = str((sentinel_payload or {}).get("token") or "").strip()
    if not token:
        logger.error(f"[线程 {thread_id}] [错误] Sentinel 响应里缺少 token")
        return {}

    proof = ""
    pow_config = (
        sentinel_payload.get("proofofwork")
        if isinstance(sentinel_payload, dict)
        else {}
    )
    if isinstance(pow_config, dict) and pow_config.get("required"):
        difficulty = str(pow_config.get("difficulty") or "").strip().lower()
        logger.info(
            f"[线程 {thread_id}] [信息] Sentinel 要求 POW，开始求解，来源={sentinel_payload.get('_sentinel_source') or 'unknown'}，难度={difficulty or 'unknown'}"
        )
        proof = solve_sentinel_pow(
            seed=str(pow_config.get("seed") or ""),
            difficulty=difficulty,
            thread_id=thread_id,
        )
        if not proof:
            return {}

    sidecar_result = run_sentinel_vm_sidecar(
        payload=sentinel_payload,
        did=device_id,
        flow=flow_name,
        requirements_token=requirements_token,
        proof=proof,
        user_agent=random_user_agent(),
        script_sources=SENTINEL_SCRIPT_SOURCES,
    )
    turnstile_value = str((sidecar_result or {}).get("turnstile_t") or "").strip()
    so_token = str((sidecar_result or {}).get("openai_sentinel_so_token") or "").strip()
    if turnstile_value:
        logger.info(
            f"[线程 {thread_id}] [信息] Sentinel sidecar 已生成 turnstile t，flow={flow_name}，len={len(turnstile_value)}"
        )
    elif sidecar_result and sidecar_result.get("turnstile_error"):
        logger.warning(
            f"[线程 {thread_id}] [警告] Sentinel sidecar 计算 t 失败，flow={flow_name}: "
            f"{str(sidecar_result.get('turnstile_error') or '')[:240]}"
        )
    if so_token:
        logger.info(
            f"[线程 {thread_id}] [信息] Sentinel sidecar 已生成 SO-Token，flow={flow_name}"
        )

    header = json.dumps(
        {
            "p": proof,
            "t": turnstile_value,
            "c": token,
            "id": device_id,
            "flow": flow_name,
        },
        ensure_ascii=False,
        separators=(",", ":"),
    )
    return {
        "header": header,
        "so_token": so_token,
        "payload": sentinel_payload,
        "proof": proof,
        "requirements_token": requirements_token,
        "sidecar": sidecar_result or {},
    }


def request_sentinel_payload(
    *,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    flow: str = "authorize_continue",
    request_body: str = "",
) -> dict:
    """请求 Sentinel 原始 payload。

    用于后续继续逆向 turnstile.dx / so.collector_dx / so.snapshot_dx。
    成功返回 dict，失败返回空 dict。
    """
    device_id = str(did or "").strip()
    if not device_id:
        logger.error(f"[线程 {thread_id}] [错误] 无法获取 Device ID，Sentinel 请求已跳过")
        return {}

    flow_name = str(flow or "authorize_continue").strip() or "authorize_continue"
    body = str(request_body or "").strip()
    if not body:
        body = json.dumps(
            {"p": "", "id": device_id, "flow": flow_name},
            ensure_ascii=False,
            separators=(",", ":"),
        )

    candidates = (
        (
            "sentinel.openai.com",
            "https://sentinel.openai.com/backend-api/sentinel/req",
            "https://sentinel.openai.com",
            SENTINEL_FRAME_URL,
        ),
        (
            "chatgpt.com",
            "https://chatgpt.com/backend-api/sentinel/req",
            "https://chatgpt.com",
            SENTINEL_CHATGPT_FRAME_URL,
        ),
    )
    last_error = ""

    for candidate_name, candidate_url, candidate_origin, candidate_referer in candidates:
        try:
            resp = requests.post(
                candidate_url,
                headers={
                    "origin": candidate_origin,
                    "referer": candidate_referer,
                    "content-type": "text/plain;charset=UTF-8",
                    "cookie": f"oai-did={urllib.parse.quote(device_id)}",
                },
                data=body,
                proxies=proxies,
                impersonate=impersonate,
                timeout=15,
            )
        except Exception as exc:
            last_error = str(exc)
            logger.warning(
                f"[线程 {thread_id}] [警告] Sentinel 请求异常（{candidate_name}）: {exc}"
            )
            continue

        if resp.status_code != 200:
            last_error = f"status={resp.status_code}"
            logger.warning(
                f"[线程 {thread_id}] [警告] Sentinel 请求失败（{candidate_name}），状态码: {resp.status_code}"
            )
            continue

        try:
            sentinel_payload = resp.json() if resp.content else {}
        except Exception as exc:
            last_error = f"json_error={exc}"
            logger.warning(
                f"[线程 {thread_id}] [警告] Sentinel 响应解析失败（{candidate_name}）: {exc}"
            )
            continue

        token = str((sentinel_payload or {}).get("token") or "").strip()
        if not token:
            last_error = "missing_token"
            logger.warning(
                f"[线程 {thread_id}] [警告] Sentinel 响应里缺少 token（{candidate_name}）"
            )
            continue

        if isinstance(sentinel_payload, dict):
            sentinel_payload["_sentinel_source"] = candidate_name
            turnstile_required = bool(
                isinstance(sentinel_payload.get("turnstile"), dict)
                and sentinel_payload.get("turnstile", {}).get("required")
            )
            session_observer_required = bool(
                isinstance(sentinel_payload.get("so"), dict)
                and sentinel_payload.get("so", {}).get("required")
            )
            logger.info(
                f"[线程 {thread_id}] [信息] Sentinel payload 已获取，来源={candidate_name}，"
                f"turnstile_required={turnstile_required}，so_required={session_observer_required}"
            )
            return sentinel_payload

    logger.error(
        f"[线程 {thread_id}] [错误] Sentinel 请求全部失败，flow={flow_name}，last_error={last_error or 'unknown'}"
    )
    return {}
