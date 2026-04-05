# -*- coding: utf-8 -*-
"""Token 提取策略模块。

封装了从 OpenAI/ChatGPT 获取 Token 的多种策略：
1. 复用当前 session 免密获取
2. 从 Cookie / client_auth_session_dump 中解析 workspace 后提交获取
3. 通过 ChatGPT session 接口兜底获取
4. 使用 session_token 直接刷新 access_token
5. 账号密码重新登录获取（支持 organization 选择）
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Set

from curl_cffi import requests

from .oauth import (
    AUTH_URL,
    CHATGPT_SESSION_URL,
    DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS,
    OAuthStart,
    RETRYABLE_GATEWAY_STATUSES,
    SESSION_API_REQUEST_TIMEOUT_SECONDS,
    _normalize_code_values,
    _parse_json_object,
    _session_fallback_expired_at,
    extract_continue_url_from_response,
    extract_workspaces_from_auth_cookie,
    follow_oauth_redirect_chain,
    generate_oauth_url,
    oauth_authorize_url,
    post_email_otp_validate,
    prime_oauth_session,
    response_text_preview,
    submit_callback_url,
)
from ..mail.providers import TempMailbox
from ..sentinel import request_sentinel_header
from .session_refresh import TokenRefreshManager

logger = logging.getLogger("openai_register")


def _proxy_url_from_proxies(proxies: Any) -> str:
    if isinstance(proxies, str):
        return str(proxies or "").strip()
    if isinstance(proxies, dict):
        for key in ("https", "http"):
            candidate = str(proxies.get(key) or "").strip()
            if candidate:
                return candidate
    return ""


def _get_cookie_value(session: Any, *cookie_names: str) -> str:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return ""
    for cookie_name in cookie_names:
        try:
            value = str(cookies.get(cookie_name) or "").strip()
        except Exception:
            value = ""
        if value:
            return value
    jar = getattr(cookies, "jar", None)
    if jar is None:
        return ""
    target_names = {str(name or "").strip() for name in cookie_names if str(name or "").strip()}
    for item in list(jar):
        name = str(getattr(item, "name", "") or "").strip()
        if name not in target_names:
            continue
        value = str(getattr(item, "value", "") or "").strip()
        if value:
            return value
    return ""


def _get_next_auth_state_cookie(session: Any) -> str:
    return _get_cookie_value(
        session,
        "__Secure-next-auth.state",
        "next-auth.state",
    )


def _get_next_auth_callback_url_cookie(session: Any) -> str:
    return _get_cookie_value(
        session,
        "__Secure-next-auth.callback-url",
        "next-auth.callback-url",
    )


def _decode_next_auth_callback_url_cookie(raw_value: str) -> str:
    value = str(raw_value or "").strip()
    if not value:
        return ""
    try:
        from urllib.parse import unquote

        return str(unquote(value) or "").strip()
    except Exception:
        return value


def _looks_like_next_auth_state_cookie(raw_value: str) -> bool:
    value = str(raw_value or "").strip()
    if not value:
        return False
    parts = value.split(".")
    return len(parts) == 5 and all(part != "" for part in parts)


def _auth_url(url: str) -> str:
    candidate = str(url or "").strip()
    if not candidate:
        return ""
    return urllib.parse.urljoin(AUTH_URL, candidate)


def _extract_callback_url(value: str) -> str:
    candidate = _auth_url(value)
    if not candidate:
        return ""
    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    code = str((query.get("code") or [""])[0] or "").strip()
    state = str((query.get("state") or [""])[0] or "").strip()
    if code and state:
        return candidate
    return ""


def _is_chatgpt_web_callback_url(value: str) -> bool:
    candidate = str(value or "").strip()
    if not candidate:
        return False
    try:
        parsed = urllib.parse.urlparse(candidate)
    except Exception:
        return False
    hostname = str(parsed.hostname or "").strip().lower()
    path = str(parsed.path or "").strip().lower()
    if hostname not in {"chatgpt.com", "www.chatgpt.com"}:
        return False
    return path == "/api/auth/callback/openai"


def _extract_callback_url_from_exception(exc: Exception) -> str:
    matched = re.search(r"(https?://(?:localhost|chatgpt\.com)[^\s'\"\\]+)", str(exc or ""))
    if not matched:
        return ""
    return _extract_callback_url(matched.group(1))


def _finalize_chatgpt_web_callback(
    session: Any,
    callback_url: str,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    """消费 ChatGPT Web callback，优先转成 next-auth/session token。"""
    candidate = str(callback_url or "").strip()
    if not _is_chatgpt_web_callback_url(candidate):
        return None

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    query_state = str((query.get("state") or [""])[0] or "").strip()
    query_code = str((query.get("code") or [""])[0] or "").strip()
    if not query_state or not query_code:
        logger.warning(f"[线程 {thread_id}] [警告] ChatGPT Web callback 缺少 code/state，已跳过")
        return None

    pre_state_cookie = _get_next_auth_state_cookie(session)
    pre_callback_url_cookie = _decode_next_auth_callback_url_cookie(
        _get_next_auth_callback_url_cookie(session)
    )
    pre_session_token = _extract_session_token(session)
    if not pre_state_cookie:
        logger.warning(
            f"[线程 {thread_id}] [警告] ChatGPT Web callback 命中，但缺少 next-auth.state cookie，"
            "暂不信任该 callback"
        )
        return None
    if not _looks_like_next_auth_state_cookie(pre_state_cookie):
        logger.warning(
            f"[线程 {thread_id}] [警告] next-auth.state cookie 形态异常，长度={len(pre_state_cookie)}"
        )
    if pre_callback_url_cookie and not (
        pre_callback_url_cookie == "/"
        or pre_callback_url_cookie.startswith("https://chatgpt.com")
        or pre_callback_url_cookie.startswith("https://www.chatgpt.com")
    ):
        logger.warning(
            f"[线程 {thread_id}] [警告] next-auth.callback-url cookie 指向异常值: {pre_callback_url_cookie}"
        )

    logger.info(f"[线程 {thread_id}] [信息] 检测到 ChatGPT Web callback，准备先消费 callback 再提取 token")
    try:
        session.get(
            candidate,
            allow_redirects=True,
            timeout=20,
            headers={
                "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "referer": "https://chatgpt.com/",
            },
        )
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] 消费 ChatGPT callback 失败: {exc}")

    post_state_cookie = _get_next_auth_state_cookie(session)
    post_callback_url_cookie = _decode_next_auth_callback_url_cookie(
        _get_next_auth_callback_url_cookie(session)
    )
    post_session_token = _extract_session_token(session)
    auth_cookie = str(session.cookies.get("oai-client-auth-session") or "").strip()
    state_cookie_rotated = bool(post_state_cookie != pre_state_cookie)
    state_cookie_cleared = bool(pre_state_cookie and not post_state_cookie)
    session_token_created = bool(not pre_session_token and post_session_token)
    callback_cookie_changed = bool(post_callback_url_cookie != pre_callback_url_cookie)
    logger.info(
        f"[线程 {thread_id}] [信息] ChatGPT Web callback 校验："
        f"state_cookie_present={bool(pre_state_cookie)} "
        f"state_cookie_rotated={state_cookie_rotated} "
        f"state_cookie_cleared={state_cookie_cleared} "
        f"session_token_created={session_token_created} "
        f"callback_cookie_changed={callback_cookie_changed} "
        f"auth_cookie_present={bool(auth_cookie)}"
    )

    token_json = try_token_via_session_cookie(
        session,
        thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json

    token_json = try_token_via_session_api(session, thread_id)
    if token_json:
        return token_json

    token_json = try_token_via_workspace_select(
        session,
        oauth=None,
        auth_cookie=auth_cookie,
        thread_id=thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json

    return None


def _extract_token_from_web_session(
    session: Any,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    """在 Web callback / redirect 被消费后，优先从当前会话直接提 token。"""
    token_json = try_token_via_session_cookie(
        session,
        thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json
    return try_token_via_session_api(session, thread_id)


def _find_first_string_by_keys(
    payload: Any,
    keys: Set[str],
    *,
    max_nodes: int = 80,
) -> str:
    if not keys:
        return ""
    seen_ids: Set[int] = set()
    queue: List[Any] = [payload]
    visited = 0
    while queue and visited < max_nodes:
        node = queue.pop(0)
        visited += 1
        if id(node) in seen_ids:
            continue
        seen_ids.add(id(node))
        if isinstance(node, dict):
            for key, value in node.items():
                key_text = str(key or "").strip()
                if key_text in keys:
                    candidate = str(value or "").strip()
                    if candidate:
                        return candidate
                if isinstance(value, (dict, list)):
                    queue.append(value)
        elif isinstance(node, list):
            for item in node:
                if isinstance(item, (dict, list)):
                    queue.append(item)
    return ""


def _session_payload_summary(payload: Dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return "payload=non_dict"
    top_keys = ",".join(sorted(str(key or "") for key in payload.keys())[:12])
    user = payload.get("user") if isinstance(payload.get("user"), dict) else {}
    account = payload.get("account") if isinstance(payload.get("account"), dict) else {}
    return (
        f"keys=[{top_keys}] "
        f"user_keys={[str(k or '') for k in list(user.keys())[:8]]} "
        f"account_keys={[str(k or '') for k in list(account.keys())[:8]]}"
    )


def _extract_warning_banner_summary(payload: Dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    banner = payload.get("WARNING_BANNER")
    if banner is None:
        return ""
    if isinstance(banner, str):
        return banner[:240]
    if isinstance(banner, dict):
        pieces = []
        for key in ("title", "message", "description", "text", "body"):
            value = str(banner.get(key) or "").strip()
            if value:
                pieces.append(f"{key}={value[:120]}")
        return " ".join(pieces)
    return str(banner)[:240]


def _client_auth_session_summary(payload: Dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return "client_auth_session=non_dict"
    workspaces = payload.get("workspaces") if isinstance(payload.get("workspaces"), list) else []
    return (
        f"keys={[str(k or '') for k in list(payload.keys())[:12]]} "
        f"workspace_count={len(workspaces)} "
        f"email_verified={payload.get('email_verified')} "
        f"session_id={str(payload.get('session_id') or '')[:80]} "
        f"name_present={bool(str(payload.get('name') or '').strip())} "
        f"birthdate_present={bool(str(payload.get('birthdate') or '').strip())}"
    )


def _refresh_token_json_from_explicit_session_token(
    session_token: str,
    *,
    thread_id: int,
    proxy_url: str = "",
) -> Optional[str]:
    token = str(session_token or "").strip()
    if not token:
        return None
    refresh_result = TokenRefreshManager(proxy_url=proxy_url or None).refresh_by_session_token(token)
    if not refresh_result.success:
        logger.warning(
            f"[线程 {thread_id}] [警告] 显式 sessionToken 刷新失败: {refresh_result.error_message or 'unknown'}"
        )
        return None
    logger.info(f"[线程 {thread_id}] [信息] 已通过响应中的 sessionToken 直接刷新 access_token")
    return _build_session_refresh_token_json(token, refresh_result)


def _extract_session_token(session: Any) -> str:
    return _get_cookie_value(
        session,
        "__Secure-next-auth.session-token",
        "next-auth.session-token",
    )


def _build_session_refresh_token_json(
    session_token: str,
    refresh_result: Any,
) -> str:
    now = int(time.time())
    expired = (
        refresh_result.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ")
        if getattr(refresh_result, "expires_at", None) is not None
        else time.strftime(
            "%Y-%m-%dT%H:%M:%SZ",
            time.gmtime(now + DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS),
        )
    )
    payload = {
        "id_token": "",
        "access_token": str(getattr(refresh_result, "access_token", "") or "").strip(),
        "refresh_token": str(getattr(refresh_result, "refresh_token", "") or "").strip(),
        "account_id": str(getattr(refresh_result, "account_id", "") or "").strip(),
        "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "email": str(getattr(refresh_result, "email", "") or "").strip(),
        "type": "session_token_refresh",
        "expired": expired,
        "session_token": str(getattr(refresh_result, "session_token", "") or session_token).strip(),
    }
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":"))


def _refresh_tokens_from_session_cookie(
    session: Any,
    *,
    thread_id: int,
    proxy_url: str = "",
) -> Optional[str]:
    session_token = _extract_session_token(session)
    if not session_token:
        return None
    logger.info(f"[线程 {thread_id}] [信息] 检测到 next-auth session_token，尝试直接刷新 access_token")
    refresh_result = TokenRefreshManager(proxy_url=proxy_url or None).refresh_by_session_token(session_token)
    if not refresh_result.success:
        logger.warning(
            f"[线程 {thread_id}] [警告] session token refresh failed: {refresh_result.error_message or 'unknown'}"
        )
        return None
    logger.info(f"[线程 {thread_id}] [信息] session token refresh succeeded")
    return _build_session_refresh_token_json(session_token, refresh_result)


def _decode_oauth_session_cookie(session: Any) -> Dict[str, Any]:
    cookies = getattr(session, "cookies", None)
    if cookies is None:
        return {}
    jar = getattr(cookies, "jar", None)
    cookie_items = list(jar) if jar is not None else []
    raw_cookie = str(cookies.get("oai-client-auth-session") or "").strip()
    if raw_cookie:
        cookie_items.insert(0, type("CookieItem", (), {"name": "oai-client-auth-session", "value": raw_cookie})())
    for item in cookie_items:
        name = str(getattr(item, "name", "") or "").strip()
        if "oai-client-auth-session" not in name:
            continue
        raw_value = str(getattr(item, "value", "") or "").strip()
        if not raw_value:
            continue
        candidates = [raw_value]
        try:
            from urllib.parse import unquote

            decoded = unquote(raw_value)
            if decoded != raw_value:
                candidates.append(decoded)
        except Exception:
            pass
        for candidate in candidates:
            try:
                value = candidate
                if (value.startswith('"') and value.endswith('"')) or (
                    value.startswith("'") and value.endswith("'")
                ):
                    value = value[1:-1]
                part = value.split(".")[0] if "." in value else value
                pad = "=" * ((4 - (len(part) % 4)) % 4)
                decoded = base64.urlsafe_b64decode((part + pad).encode("ascii"))
                data = json.loads(decoded.decode("utf-8"))
                if isinstance(data, dict):
                    return data
            except Exception:
                continue
    return {}


def _fetch_client_auth_session_dump(session: Any, thread_id: int) -> Dict[str, Any]:
    try:
        resp = session.get(
            "https://auth.openai.com/api/accounts/client_auth_session_dump",
            headers={
                "accept": "application/json",
                "referer": "https://auth.openai.com/add-phone",
            },
            timeout=15,
        )
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] client_auth_session_dump 请求失败: {exc}")
        return {}

    if resp.status_code != 200:
        logger.warning(
            f"[线程 {thread_id}] [警告] client_auth_session_dump 状态异常: {resp.status_code}，"
            f"摘要: {response_text_preview(resp)}"
        )
        return {}

    try:
        payload = resp.json() if resp.content else {}
    except Exception:
        payload = _parse_json_object(getattr(resp, "text", ""))

    session_payload = payload.get("client_auth_session") if isinstance(payload, dict) else None
    if isinstance(session_payload, dict):
        logger.info(
            f"[线程 {thread_id}] [信息] client_auth_session_dump 摘要：{_client_auth_session_summary(session_payload)}"
        )
        return session_payload
    return {}


def _load_oauth_session_payload(session: Any, thread_id: int) -> Dict[str, Any]:
    cookie_payload = _decode_oauth_session_cookie(session)
    workspaces = cookie_payload.get("workspaces") or []
    if isinstance(workspaces, list) and workspaces:
        return cookie_payload
    dump_payload = _fetch_client_auth_session_dump(session, thread_id)
    dump_workspaces = dump_payload.get("workspaces") if isinstance(dump_payload, dict) else None
    if isinstance(dump_workspaces, list) and dump_workspaces:
        return dump_payload
    return cookie_payload or dump_payload or {}


def _try_workspace_and_org_selection(
    session: Any,
    oauth: Optional[OAuthStart],
    workspace_id: str,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    select_resp = session.post(
        "https://auth.openai.com/api/accounts/workspace/select",
        headers={
            "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
            "content-type": "application/json",
            "accept": "application/json",
        },
        json={"workspace_id": workspace_id},
    )
    if select_resp.status_code != 200:
        logger.warning(f"[线程 {thread_id}] [警告] 选择 workspace 失败，状态码: {select_resp.status_code}")
        continue_url = extract_continue_url_from_response(select_resp)
        if continue_url:
            if oauth is not None:
                token_json = follow_oauth_redirect_chain(session, continue_url, oauth, thread_id)
                if token_json:
                    return token_json
            token_json = _finalize_chatgpt_web_callback(
                session,
                continue_url,
                thread_id,
                proxy_url=proxy_url,
            )
            if token_json:
                return token_json
            return _extract_token_from_web_session(
                session,
                thread_id,
                proxy_url=proxy_url,
            )
        return None

    try:
        select_payload = select_resp.json() if select_resp.content else {}
    except Exception:
        select_payload = {}

    orgs = ((select_payload.get("data") or {}).get("orgs") or []) if isinstance(select_payload, dict) else []
    if isinstance(orgs, list) and orgs:
        first_org = orgs[0] or {}
        org_id = str(first_org.get("id") or "").strip()
        projects = first_org.get("projects") or []
        project_id = ""
        if isinstance(projects, list) and projects:
            project_id = str((projects[0] or {}).get("id") or "").strip()
        if org_id:
            org_body: Dict[str, str] = {"org_id": org_id}
            if project_id:
                org_body["project_id"] = project_id
            org_resp = session.post(
                "https://auth.openai.com/api/accounts/organization/select",
                headers={
                    "referer": "https://auth.openai.com/sign-in-with-chatgpt/codex/consent",
                    "content-type": "application/json",
                    "accept": "application/json",
                },
                json=org_body,
            )
            if org_resp.status_code == 200 or 300 <= org_resp.status_code < 400:
                org_continue_url = extract_continue_url_from_response(org_resp)
                if org_continue_url:
                    if oauth is not None:
                        token_json = follow_oauth_redirect_chain(session, org_continue_url, oauth, thread_id)
                        if token_json:
                            return token_json
                    token_json = _finalize_chatgpt_web_callback(
                        session,
                        org_continue_url,
                        thread_id,
                        proxy_url=proxy_url,
                    )
                    if token_json:
                        return token_json
                    return _extract_token_from_web_session(
                        session,
                        thread_id,
                        proxy_url=proxy_url,
                    )
            logger.warning(
                f"[线程 {thread_id}] [警告] 选择 organization 失败，状态码: {org_resp.status_code}"
            )

    continue_url = extract_continue_url_from_response(select_resp)
    if not continue_url:
        logger.warning(f"[线程 {thread_id}] [警告] workspace/select 响应里缺少 continue_url")
        return None

    logger.info(f"[线程 {thread_id}] [信息] 已获取 workspace，继续跟随授权跳转链")
    if oauth is not None:
        token_json = follow_oauth_redirect_chain(session, continue_url, oauth, thread_id)
        if token_json:
            return token_json
    token_json = _finalize_chatgpt_web_callback(
        session,
        continue_url,
        thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json
    return _extract_token_from_web_session(
        session,
        thread_id,
        proxy_url=proxy_url,
    )


# ---------------------------------------------------------------------------
# 策略 1: 复用当前 session 免密获取 token
# ---------------------------------------------------------------------------


def try_token_via_existing_session(
    session: Any,
    oauth: OAuthStart,
    thread_id: int,
) -> Optional[str]:
    """尝试复用当前 session 免密获取 token。"""
    logger.info(f"[线程 {thread_id}] [信息] 尝试复用当前 session 免密获取 token")
    return follow_oauth_redirect_chain(
        session,
        oauth_authorize_url(oauth, prompt=None),
        oauth,
        thread_id,
    )


def try_token_via_continue_url(
    session: Any,
    oauth: OAuthStart,
    continue_url: str,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    """尝试直接跟随某个 continue_url 获取 token。"""
    candidate = str(continue_url or "").strip()
    if not candidate:
        return None
    logger.info(f"[线程 {thread_id}] [信息] 尝试直接跟随 continue_url 获取 token")
    callback_url = _extract_callback_url(candidate)
    if callback_url:
        try:
            return submit_callback_url(
                callback_url=callback_url,
                expected_state=oauth.state,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
            )
        except Exception as exc:
            logger.warning(f"[线程 {thread_id}] [警告] continue_url 直接回调换 token 失败: {exc}")
    token_json = follow_oauth_redirect_chain(session, candidate, oauth, thread_id)
    if token_json:
        return token_json
    token_json = _finalize_chatgpt_web_callback(
        session,
        candidate,
        thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json
    auth_cookie = str(session.cookies.get("oai-client-auth-session") or "").strip()
    token_json = try_token_via_workspace_select(
        session,
        oauth,
        auth_cookie,
        thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json
    return _extract_token_from_web_session(
        session,
        thread_id,
        proxy_url=proxy_url,
    )


def try_token_via_session_cookie(
    session: Any,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    """尝试通过 next-auth session_token 直接刷新 access_token。"""
    return _refresh_tokens_from_session_cookie(
        session,
        thread_id=thread_id,
        proxy_url=proxy_url,
    )


# ---------------------------------------------------------------------------
# 策略 2: 从 Cookie / dump 中解析 workspace 后提交获取
# ---------------------------------------------------------------------------


def try_token_via_workspace_select(
    session: Any,
    oauth: Optional[OAuthStart],
    auth_cookie: str,
    thread_id: int,
    *,
    proxy_url: str = "",
) -> Optional[str]:
    """从授权 Cookie / dump 中解析 workspace 并选择后获取 token。"""
    workspaces = extract_workspaces_from_auth_cookie(auth_cookie)
    if not workspaces:
        session_payload = _load_oauth_session_payload(session, thread_id)
        workspaces = [
            item
            for item in (session_payload.get("workspaces") or [])
            if isinstance(item, dict)
        ]
    if not workspaces:
        logger.warning(f"[线程 {thread_id}] [警告] 授权 Cookie 存在，但暂未解析到 workspace")
        return None

    selected_workspace = workspaces[0] or {}
    workspace_id = str(selected_workspace.get("id") or "").strip()
    if not workspace_id:
        logger.warning(f"[线程 {thread_id}] [警告] workspace 信息存在，但无法解析 workspace_id")
        return None

    workspace_kind = str(selected_workspace.get("kind") or "").strip() or "unknown"
    workspace_name = str(selected_workspace.get("name") or "").strip() or "(null)"
    logger.info(
        f"[线程 {thread_id}] [信息] 已解析 workspace: count={len(workspaces)}, "
        f"id={workspace_id}, kind={workspace_kind}, name={workspace_name}"
    )
    token_json = _try_workspace_and_org_selection(
        session,
        oauth,
        workspace_id,
        thread_id,
        proxy_url=proxy_url,
    )
    if token_json:
        return token_json
    return _extract_token_from_web_session(
        session,
        thread_id,
        proxy_url=proxy_url,
    )


# ---------------------------------------------------------------------------
# 策略 3: 通过 ChatGPT session 接口兜底获取
# ---------------------------------------------------------------------------


def try_token_via_session_api(session: Any, thread_id: int) -> Optional[str]:
    """通过 chatgpt session 接口兜底提取 token。"""
    logger.info(f"[线程 {thread_id}] [信息] 尝试通过 chatgpt session 接口兜底提取 token")

    last_summary = ""
    for attempt in range(1, 4):
        try:
            resp = session.get(
                CHATGPT_SESSION_URL,
                headers={
                    "accept": "application/json,text/plain,*/*",
                    "referer": "https://chatgpt.com/",
                },
                timeout=SESSION_API_REQUEST_TIMEOUT_SECONDS,
            )
        except Exception as exc:
            logger.warning(f"[线程 {thread_id}] [警告] 读取 chatgpt session 接口失败: {exc}")
            return None

        if resp.status_code != 200:
            logger.warning(
                f"[线程 {thread_id}] [警告] chatgpt session 接口状态异常: {resp.status_code}，"
                f"摘要: {response_text_preview(resp)}"
            )
            return None

        try:
            payload = resp.json() if resp.content else {}
        except Exception:
            payload = _parse_json_object(getattr(resp, "text", ""))

        if not isinstance(payload, dict) or not payload:
            logger.warning(f"[线程 {thread_id}] [警告] chatgpt session 接口未返回有效 JSON")
            return None

        access_token = (
            str(payload.get("accessToken") or "").strip()
            or _find_first_string_by_keys(
                payload,
                {"accessToken", "access_token"},
            )
        )
        session_token = (
            str(payload.get("sessionToken") or "").strip()
            or _find_first_string_by_keys(
                payload,
                {"sessionToken", "session_token"},
            )
        )
        last_summary = _session_payload_summary(payload)

        if not access_token and session_token:
            token_json = _refresh_token_json_from_explicit_session_token(
                session_token,
                thread_id=thread_id,
                proxy_url=_proxy_url_from_proxies(getattr(session, "proxies", None)),
            )
            if token_json:
                return token_json

        if not access_token:
            if attempt < 3:
                warning_banner = _extract_warning_banner_summary(payload)
                logger.info(
                    f"[线程 {thread_id}] [信息] chatgpt session 第 {attempt}/3 次暂未拿到 accessToken，"
                    f"准备稍后重试；{last_summary}"
                    f"{f' warning_banner={warning_banner}' if warning_banner else ''}"
                )
                time.sleep(attempt)
                continue
            warning_banner = _extract_warning_banner_summary(payload)
            logger.warning(
                f"[线程 {thread_id}] [警告] chatgpt session 接口响应中缺少 accessToken；{last_summary}"
                f"{f' warning_banner={warning_banner}' if warning_banner else ''}"
            )
            return None

        user_info = payload.get("user") if isinstance(payload.get("user"), dict) else {}
        account_info = payload.get("account") if isinstance(payload.get("account"), dict) else {}
        email = str(user_info.get("email") or "").strip()
        account_id = str(
            user_info.get("id")
            or account_info.get("id")
            or _find_first_string_by_keys(payload, {"account_id", "accountId"})
            or ""
        ).strip()
        now = int(time.time())

        config = {
            "id_token": "",
            "access_token": access_token,
            "refresh_token": "",
            "account_id": account_id,
            "last_refresh": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
            "email": email,
            "type": "chatgpt_session_fallback",
            "expired": _session_fallback_expired_at(payload),
        }
        if session_token:
            config["session_token"] = session_token

        plan_type = str(account_info.get("planType") or "").strip()
        if plan_type:
            config["plan_type"] = plan_type

        logger.info(
            f"[线程 {thread_id}] [信息] 已通过 chatgpt session 接口提取 access_token"
            f"{f'，email={email}' if email else ''}"
            f"{f'，account_id={account_id}' if account_id else ''}"
        )
        return json.dumps(config, ensure_ascii=False, separators=(",", ":"))

    if last_summary:
        logger.warning(f"[线程 {thread_id}] [警告] chatgpt session 轮询结束仍未成功；{last_summary}")
    return None


# ---------------------------------------------------------------------------
# 策略 4: 账号密码重新登录获取
# ---------------------------------------------------------------------------


def try_token_via_password_login(
    *,
    email: str,
    password: str,
    mailbox: Optional[TempMailbox] = None,
    used_codes: Optional[Set[str]] = None,
    oauth: OAuthStart,
    proxies: Any,
    impersonate: str,
    thread_id: int,
    get_oai_code_fn: Callable[..., str],
    get_mailbox_message_snapshot_fn: Callable[..., Set[str]],
) -> Optional[str]:
    """使用账号密码重新登录以获取 token。"""
    account = str(email or "").strip()
    pwd = str(password or "").strip()
    if not account or not pwd:
        return None

    proxy_url = _proxy_url_from_proxies(proxies)
    logger.info(f"[线程 {thread_id}] [信息] 当前 session 未拿到 token，尝试账号密码重新登录")
    login_session = requests.Session(proxies=proxies, impersonate=impersonate)
    login_oauth = generate_oauth_url(
        redirect_uri=oauth.redirect_uri,
        scope=oauth.scope,
    )
    ignored_codes = _normalize_code_values(used_codes)

    def _bootstrap_login_session() -> str:
        prime_oauth_session(
            login_session,
            oauth_authorize_url(login_oauth, prompt="login"),
            thread_id,
        )
        return str(login_session.cookies.get("oai-did") or "").strip()

    def _post_login_authorize_continue(current_did: str) -> Any:
        sentinel_header = request_sentinel_header(
            did=current_did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
            flow="authorize_continue",
        )
        if not sentinel_header:
            return None
        return login_session.post(
            "https://auth.openai.com/api/accounts/authorize/continue",
            headers={
                "referer": "https://auth.openai.com/sign-in",
                "accept": "application/json",
                "content-type": "application/json",
                "openai-sentinel-token": sentinel_header,
            },
            data=json.dumps(
                {
                    "username": {"value": account, "kind": "email"},
                    "screen_hint": "login",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )

    def _post_login_password_verify(current_did: str) -> Any:
        password_headers = {
            "referer": "https://auth.openai.com/log-in/password",
            "accept": "application/json",
            "content-type": "application/json",
        }
        password_sentinel = request_sentinel_header(
            did=current_did,
            proxies=proxies,
            impersonate=impersonate,
            thread_id=thread_id,
            flow="password_verify",
        )
        if password_sentinel:
            password_headers["openai-sentinel-token"] = password_sentinel
        return login_session.post(
            "https://auth.openai.com/api/accounts/password/verify",
            headers=password_headers,
            data=json.dumps(
                {"password": pwd},
                ensure_ascii=False,
                separators=(",", ":"),
            ),
        )

    def _extract_token_after_password_conflict(continue_url: str = "") -> Optional[str]:
        token_json = try_token_via_session_cookie(
            login_session,
            thread_id,
            proxy_url=proxy_url,
        )
        if token_json:
            return token_json
        token_json = try_token_via_session_api(login_session, thread_id)
        if token_json:
            return token_json
        auth_cookie = str(login_session.cookies.get("oai-client-auth-session") or "").strip()
        token_json = try_token_via_workspace_select(
            login_session,
            login_oauth,
            auth_cookie,
            thread_id,
            proxy_url=proxy_url,
        )
        if token_json:
            return token_json
        if continue_url:
            token_json = try_token_via_continue_url(
                login_session,
                login_oauth,
                continue_url,
                thread_id,
                proxy_url=proxy_url,
            )
            if token_json:
                return token_json
        return None

    try:
        did = _bootstrap_login_session()
        continue_resp = _post_login_authorize_continue(did)
        if continue_resp is None:
            return None
        if continue_resp.status_code == 400 and "invalid_auth_step" in str(getattr(continue_resp, "text", "") or "").lower():
            logger.info(f"[线程 {thread_id}] [信息] 登录预处理遇到 invalid_auth_step，重建认证上下文后重试一次")
            did = _bootstrap_login_session()
            continue_resp = _post_login_authorize_continue(did)
            if continue_resp is None:
                return None
        if continue_resp.status_code not in (200, 204):
            logger.warning(
                f"[线程 {thread_id}] [警告] 账号密码登录预处理失败，状态码: {continue_resp.status_code}"
            )
            return None

        existing_message_ids = (
            get_mailbox_message_snapshot_fn(mailbox, thread_id, proxies) if mailbox else set()
        )
        login_resp = _post_login_password_verify(did)
        if login_resp.status_code != 200:
            continue_url = extract_continue_url_from_response(login_resp)
            preview = response_text_preview(login_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] 账号密码登录失败，状态码: {login_resp.status_code}，摘要: {preview}"
            )
            if login_resp.status_code == 409:
                token_json = _extract_token_after_password_conflict(continue_url)
                if token_json:
                    return token_json
                logger.info(f"[线程 {thread_id}] [信息] password_verify 命中 409，重建认证上下文后重试一次")
                did = _bootstrap_login_session()
                continue_resp = _post_login_authorize_continue(did)
                if continue_resp is None or continue_resp.status_code not in (200, 204):
                    return _extract_token_after_password_conflict(continue_url)
                login_resp = _post_login_password_verify(did)
                if login_resp.status_code != 200:
                    continue_url = extract_continue_url_from_response(login_resp)
                    preview = response_text_preview(login_resp)
                    logger.warning(
                        f"[线程 {thread_id}] [警告] password_verify 重试后仍失败，状态码: {login_resp.status_code}，摘要: {preview}"
                    )
                    return _extract_token_after_password_conflict(continue_url)
            else:
                return None

        try:
            login_payload = login_resp.json() if login_resp.content else {}
        except Exception:
            login_payload = {}

        login_page = login_payload.get("page") or {}
        page_type = str(login_page.get("type") or "").strip()
        continue_url = extract_continue_url_from_response(login_resp)
        need_oauth_otp = (
            page_type == "email_otp_verification"
            or "email-verification" in str(continue_url or "")
            or "email-otp" in str(continue_url or "")
        )

        if need_oauth_otp:
            token_json = try_token_via_session_cookie(
                login_session,
                thread_id,
                proxy_url=proxy_url,
            )
            if token_json:
                return token_json

            if not mailbox:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 密码登录后需要邮箱验证码，但当前没有可用邮箱上下文"
                )
                return None

            logger.info(f"[线程 {thread_id}] [信息] OpenAI 已自动发送登录验证码邮件，开始等待新邮件")
            login_otp_resp = None
            for otp_attempt in range(2):
                login_code = get_oai_code_fn(
                    mailbox,
                    thread_id,
                    proxies,
                    skip_message_ids=existing_message_ids,
                    skip_codes=ignored_codes,
                )
                if not login_code:
                    logger.warning(f"[线程 {thread_id}] [警告] 未能获取登录阶段邮箱验证码")
                    return None

                login_otp_resp = post_email_otp_validate(
                    login_session,
                    code=login_code,
                    thread_id=thread_id,
                    stage_label="登录阶段",
                )
                if login_otp_resp and login_otp_resp.status_code == 200:
                    continue_url = extract_continue_url_from_response(login_otp_resp)
                    token_json = try_token_via_session_cookie(
                        login_session,
                        thread_id,
                        proxy_url=proxy_url,
                    )
                    if token_json:
                        return token_json
                    break

                status_code = getattr(login_otp_resp, "status_code", "unknown")
                if status_code not in RETRYABLE_GATEWAY_STATUSES:
                    ignored_codes.add(login_code)
                logger.warning(
                    f"[线程 {thread_id}] [警告] 登录阶段邮箱验证码校验失败，状态码: {status_code}"
                )
                if status_code == 401 and otp_attempt == 0:
                    logger.info(f"[线程 {thread_id}] [信息] 登录验证码可能命中旧邮件，准备重新等待新验证码")
                    time.sleep(2)
                    continue
                return None

            if not login_otp_resp or login_otp_resp.status_code != 200:
                return None

        auth_cookie = str(login_session.cookies.get("oai-client-auth-session") or "").strip()
        token_json = try_token_via_workspace_select(
            login_session,
            login_oauth,
            auth_cookie,
            thread_id,
            proxy_url=proxy_url,
        )
        if token_json:
            return token_json

        if continue_url:
            token_json = try_token_via_continue_url(
                login_session,
                oauth,
                continue_url,
                thread_id,
                proxy_url=proxy_url,
            )
            if token_json:
                return token_json

        auth_cookie = str(login_session.cookies.get("oai-client-auth-session") or "").strip()
        token_json = try_token_via_workspace_select(
            login_session,
            oauth,
            auth_cookie,
            thread_id,
            proxy_url=proxy_url,
        )
        if token_json:
            return token_json

        token_json = try_token_via_session_cookie(
            login_session,
            thread_id,
            proxy_url=proxy_url,
        )
        if token_json:
            return token_json

        return try_token_via_existing_session(login_session, login_oauth, thread_id)
    except Exception as exc:
        callback_url = _extract_callback_url_from_exception(exc)
        if callback_url:
            try:
                return submit_callback_url(
                    callback_url=callback_url,
                    expected_state=login_oauth.state,
                    code_verifier=login_oauth.code_verifier,
                    redirect_uri=login_oauth.redirect_uri,
                )
            except Exception:
                try:
                    token_json = _finalize_chatgpt_web_callback(
                        login_session,
                        callback_url,
                        thread_id,
                        proxy_url=proxy_url,
                    )
                    if token_json:
                        return token_json
                except Exception:
                    pass
        logger.warning(f"[线程 {thread_id}] [警告] 账号密码登录兜底失败: {exc}")
        return None
