# -*- coding: utf-8 -*-
"""共享注册辅助函数与结果类型。"""
from __future__ import annotations

import json
import logging
import random
import secrets
import socket
import string
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Tuple

from ..auth.oauth import response_text_preview
from ..config import (
    CREATE_ACCOUNT_MAX_ATTEMPTS,
    CREATE_ACCOUNT_RETRY_DELAY_SECONDS,
)
from ..mail.diagnostics import get_mailbox_wait_diagnostics
from ..mail.providers import TempMailbox
from ..sentinel import request_sentinel_header

logger = logging.getLogger("openai_register")


@dataclass
class RegistrationAttemptResult:
    """单次注册尝试的结果。"""

    success: bool = False
    token_json: str = ""
    password: str = ""
    email: str = ""
    stage: str = ""
    error_code: str = ""
    error_message: str = ""
    provider_key: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    private_context: Dict[str, Any] = field(default_factory=dict)

    def as_legacy_result(self) -> Optional[Tuple[str, str]]:
        """兼容旧版返回格式。"""
        if not self.success or not self.token_json:
            return None
        return self.token_json, self.password

# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _random_name_part(min_length: int = 4, max_length: int = 9) -> str:
    """生成随机英文名片段。"""
    length = random.randint(min_length, max_length)
    letters = string.ascii_lowercase
    value = "".join(secrets.choice(letters) for _ in range(length))
    return value.capitalize()


def _random_profile_name() -> str:
    """生成随机的全名（名 + 姓）。"""
    return f"{_random_name_part()} {_random_name_part(5, 10)}"


def _random_birthdate(start_year: int = 1990, end_year: int = 2005) -> str:
    """生成随机的出生日期字符串。"""
    start_date = datetime(start_year, 1, 1)
    end_date = datetime(end_year, 12, 31)
    day_offset = random.randint(0, (end_date - start_date).days)
    return (start_date + timedelta(days=day_offset)).strftime("%Y-%m-%d")


def _build_random_signup_profile() -> Dict[str, str]:
    """构建随机的注册资料。"""
    return {
        "name": _random_profile_name(),
        "birthdate": _random_birthdate(),
    }


def _build_request_proxies(proxy: Optional[str]) -> Any:
    """将代理字符串转为 requests 库所需的 proxies 字典。"""
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


def _generate_password(length: int = 12) -> str:
    """生成指定长度的随机密码。"""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for _ in range(length))


def _preview_response_text(resp: Any, limit: int = 600) -> str:
    """获取 HTTP 响应的预览文本。"""
    preview = response_text_preview(resp, limit=limit) if resp is not None else ""
    if preview:
        return preview
    status_code = getattr(resp, "status_code", "unknown")
    return f"status={status_code}"


def get_auto_proxy() -> Optional[str]:
    """自动检测本地代理端口并返回代理地址。"""
    common_ports = [7890, 1080, 10809, 10808, 8888]

    for port in common_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                logger.info(
                    f"[信息] 检测到本地代理端口可用: {port}"
                )
                return f"http://127.0.0.1:{port}"
    return None


def _post_create_account_with_retry(
    session: Any,
    *,
    create_account_body: str,
    did: str,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    max_attempts: int = CREATE_ACCOUNT_MAX_ATTEMPTS,
    retry_delay_seconds: int = CREATE_ACCOUNT_RETRY_DELAY_SECONDS,
) -> Optional[Any]:
    """带重试的创建账户请求。"""
    attempts = max(1, int(max_attempts))
    delay_seconds = max(0, int(retry_delay_seconds))
    last_resp = None

    for attempt in range(1, attempts + 1):
        try:
            create_account_sentinel = request_sentinel_header(
                did=did,
                proxies=proxies,
                impersonate=impersonate,
                thread_id=thread_id,
                flow="oauth_create_account",
            )
            if not create_account_sentinel:
                return None

            last_resp = session.post(
                "https://auth.openai.com/api/accounts/create_account",
                headers={
                    "referer": "https://auth.openai.com/about-you",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "openai-sentinel-token": create_account_sentinel,
                },
                data=create_account_body,
            )
        except Exception as exc:
            if attempt < attempts:
                logger.warning(
                    f"[线程 {thread_id}] [警告] create_account 请求异常，"
                    f"第 {attempt}/{attempts} 次尝试失败: {exc}；"
                    f"{delay_seconds} 秒后重试"
                )
                time.sleep(delay_seconds)
                continue
            logger.error(f"[线程 {thread_id}] [错误] create_account 请求异常: {exc}")
            return None

        status_code = getattr(last_resp, "status_code", 0)
        if status_code == 200:
            return last_resp

        if status_code in (408, 425, 429, 500, 502, 503, 504) and attempt < attempts:
            preview = response_text_preview(last_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] create_account 遇到临时错误，"
                f"状态码: {status_code}，第 {attempt}/{attempts} 次尝试；"
                f"{delay_seconds} 秒后重试。响应摘要: {preview}"
            )
            time.sleep(delay_seconds)
            continue

        return last_resp

    return last_resp


def _response_json_object(resp: Any) -> Dict[str, Any]:
    try:
        payload = resp.json() if getattr(resp, "content", b"") else {}
    except Exception:
        payload = {}
    return payload if isinstance(payload, dict) else {}


def _extract_response_error_code_message(resp: Any) -> Tuple[str, str]:
    payload = _response_json_object(resp)
    if isinstance(payload, dict):
        error_obj = payload.get("error")
        if isinstance(error_obj, dict):
            code = str(error_obj.get("code") or error_obj.get("error") or "").strip()
            message = str(
                error_obj.get("message")
                or error_obj.get("description")
                or error_obj.get("error_description")
                or ""
            ).strip()
            return code, message
        code = str(payload.get("code") or payload.get("error") or "").strip()
        message = str(
            payload.get("message") or payload.get("error_description") or ""
        ).strip()
        return code, message
    return "", _preview_response_text(resp)


def _is_invalid_auth_step(resp: Any) -> bool:
    error_code, error_message = _extract_response_error_code_message(resp)
    merged = f"{error_code} {error_message} {getattr(resp, 'text', '') or ''}".lower()
    return "invalid_auth_step" in merged


def _mailbox_public_metadata(mailbox: Optional[TempMailbox]) -> Dict[str, Any]:
    if mailbox is None:
        return {}
    return {
        "email": str(mailbox.email or "").strip(),
        "provider": str(mailbox.provider or "").strip(),
        "api_base": str(mailbox.api_base or "").strip(),
        "domain": str(mailbox.domain or "").strip(),
        "config_name": str(mailbox.config_name or "").strip(),
    }


def _mailbox_wait_failure_reason(mailbox: TempMailbox) -> Tuple[str, Dict[str, Any]]:
    diagnostics = get_mailbox_wait_diagnostics(mailbox.provider, mailbox.email)
    if diagnostics.get("aborted"):
        return "mailbox_aborted_rotation", diagnostics
    try:
        scanned = int(diagnostics.get("message_scan_count") or 0)
    except Exception:
        scanned = 0
    if scanned <= 0:
        return "mailbox_timeout_no_message", diagnostics
    return "mailbox_timeout_no_match", diagnostics


def _extract_session_token_from_session(session: Any) -> str:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return ""
    for cookie_name in ("__Secure-next-auth.session-token", "next-auth.session-token"):
        try:
            cookie_value = str(cookies.get(cookie_name) or "").strip()
        except Exception:
            cookie_value = ""
        if cookie_value:
            return cookie_value
    jar = getattr(cookies, "jar", None)
    if jar is None:
        return ""
    for item in list(jar):
        name = str(getattr(item, "name", "") or "").strip()
        if name not in {"__Secure-next-auth.session-token", "next-auth.session-token"}:
            continue
        value = str(getattr(item, "value", "") or "").strip()
        if value:
            return value
    return ""


def _enrich_token_json(
    token_json: str,
    *,
    session: Any,
    mailbox: TempMailbox,
    provider_key: str,
    metadata: Dict[str, Any],
) -> str:
    try:
        payload = json.loads(token_json)
    except Exception:
        return token_json
    if not isinstance(payload, dict):
        return token_json

    session_token = str(payload.get("session_token") or "").strip() or _extract_session_token_from_session(session)
    if session_token:
        payload["session_token"] = session_token

    payload.setdefault("email", str(metadata.get("mailbox_email") or mailbox.email or "").strip())
    payload.setdefault("created_at", datetime.now().astimezone().isoformat(timespec="seconds"))
    payload["mail_provider"] = str(mailbox.provider or provider_key or "").strip()
    payload["mailbox"] = _mailbox_public_metadata(mailbox)
    payload["registration_proxy_url"] = str(metadata.get("registration_proxy_url") or "").strip()
    payload["registration_fingerprint_profile"] = str(
        metadata.get("fingerprint_profile") or metadata.get("impersonate") or ""
    ).strip()
    payload["registration_metadata"] = dict(metadata)
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))

__all__ = [
    "RegistrationAttemptResult",
    "_build_random_signup_profile",
    "_build_request_proxies",
    "_enrich_token_json",
    "_extract_session_token_from_session",
    "_extract_response_error_code_message",
    "_generate_password",
    "_is_invalid_auth_step",
    "_mailbox_public_metadata",
    "_mailbox_wait_failure_reason",
    "_post_create_account_with_retry",
    "_preview_response_text",
    "_random_birthdate",
    "_random_name_part",
    "_random_profile_name",
    "_response_json_object",
    "get_auto_proxy",
]
