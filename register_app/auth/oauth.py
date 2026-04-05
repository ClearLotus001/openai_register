# -*- coding: utf-8 -*-
"""OAuth 授权、PKCE、回调处理与 Web Signup 逻辑。

本模块只保留与 OpenAI OAuth 认证流程直接相关的功能：
- PKCE code_verifier / code_challenge 生成
- OAuth 授权 URL 构建
- Web Signup 入口获取
- 回调 URL 解析与 Token 交换
- OAuth 重定向链跟随
- Email OTP 校验请求
- JWT/Cookie 解析工具

Sentinel / 指纹 / POW 求解 → register_app/sentinel.py
Token 提取策略 → register_app/auth/token.py
"""
import base64
import html
import hashlib
import json
import logging
import os
import re
import secrets
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

from curl_cffi import requests

from ..mail.providers import TempMailbox

logger = logging.getLogger("openai_register")

# ---------------------------------------------------------------------------
# OAuth 常量
# ---------------------------------------------------------------------------
RETRYABLE_GATEWAY_STATUSES = {502, 503, 504}
EMAIL_OTP_VALIDATE_MAX_ATTEMPTS = 3
EMAIL_OTP_VALIDATE_RETRY_DELAY_SECONDS = 2
AUTH_URL = "https://auth.openai.com/oauth/authorize"
TOKEN_URL = "https://auth.openai.com/oauth/token"
CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
DEFAULT_REDIRECT_URI = "http://localhost:1455/auth/callback"
DEFAULT_SCOPE = "openid email profile offline_access"
WEB_SIGNIN_REFERER = "https://chatgpt.com/auth/login"
WEB_SIGNUP_MAX_ATTEMPTS = 3
WEB_SIGNUP_RETRY_DELAY_SECONDS = 2
WEB_SIGNUP_REQUEST_TIMEOUT_SECONDS = 20
PRIME_OAUTH_MAX_REQUEST_ATTEMPTS = 3
PRIME_OAUTH_RETRY_DELAY_SECONDS = 2
PRIME_OAUTH_REQUEST_TIMEOUT_SECONDS = 20
CHATGPT_SESSION_URL = "https://chatgpt.com/api/auth/session"
SESSION_API_REQUEST_TIMEOUT_SECONDS = 15
DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS = 1800
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_DEBUG_DIR = os.path.join(_PROJECT_ROOT, "debug")


# ---------------------------------------------------------------------------
# 数据类
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OAuthStart:
    """OAuth 授权起始参数。"""

    auth_url: str
    state: str
    code_verifier: str
    redirect_uri: str
    scope: str


# ---------------------------------------------------------------------------
# PKCE / 编码工具
# ---------------------------------------------------------------------------


def _normalize_code_values(code_values: Optional[Set[str]] = None) -> Set[str]:
    """标准化验证码集合，去除空值和空白。"""
    if not code_values:
        return set()
    normalized: Set[str] = set()
    for item in code_values:
        value = str(item or "").strip()
        if value:
            normalized.add(value)
    return normalized


def _b64url_no_pad(raw: bytes) -> str:
    """Base64url 编码（无填充）。"""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _sha256_b64url_no_pad(s: str) -> str:
    """SHA-256 哈希后 Base64url 编码（无填充）。"""
    return _b64url_no_pad(hashlib.sha256(s.encode("ascii")).digest())


def _random_state(nbytes: int = 16) -> str:
    """生成随机 OAuth state 参数。"""
    return secrets.token_urlsafe(nbytes)


def _pkce_verifier() -> str:
    """生成 PKCE code_verifier。"""
    return secrets.token_urlsafe(64)


# ---------------------------------------------------------------------------
# 回调 URL 解析
# ---------------------------------------------------------------------------


def _parse_callback_url(callback_url: str) -> Dict[str, str]:
    """解析 OAuth 回调 URL 中的 code / state / error 等参数。"""
    candidate = str(callback_url or "").strip()
    if not candidate:
        return {"code": "", "state": "", "error": "", "error_description": ""}
    if "://" not in candidate:
        if candidate.startswith("?"):
            candidate = f"http://localhost{candidate}"
        elif "=" in candidate:
            candidate = f"http://localhost/?{candidate}"
        else:
            candidate = f"http://{candidate}"

    parsed = urllib.parse.urlparse(candidate)
    query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    fragment = urllib.parse.parse_qs(parsed.fragment, keep_blank_values=True)
    for key, values in fragment.items():
        if key not in query or not query[key]:
            query[key] = values

    def get1(k: str) -> str:
        vals = query.get(k) or fragment.get(k) or [""]
        return vals[0] if vals else ""

    code = get1("code")
    state = get1("state")
    error = get1("error")
    error_description = get1("error_description")

    if code and not state and "#" in code:
        code, state = code.split("#", 1)

    if not error and error_description:
        error, error_description = error_description, ""

    return {
        "code": code,
        "state": state,
        "error": error,
        "error_description": error_description,
    }


# ---------------------------------------------------------------------------
# JWT / Cookie 解析工具
# ---------------------------------------------------------------------------


def _jwt_claims_no_verify(id_token: str) -> Dict[str, Any]:
    """无验证地解码 JWT id_token 的 payload 部分。"""
    if not id_token or id_token.count(".") < 2:
        return {}
    payload_b64 = id_token.split(".")[1]
    pad = "=" * ((4 - (len(payload_b64) % 4)) % 4)
    try:
        payload = base64.urlsafe_b64decode((payload_b64 + pad).encode("ascii"))
        return json.loads(payload.decode("utf-8"))
    except Exception:
        return {}


def _decode_jwt_segment(seg: str) -> Dict[str, Any]:
    """解码单个 JWT/Base64 编码的段。"""
    raw = (seg or "").strip()
    if not raw:
        return {}
    pad = "=" * ((4 - (len(raw) % 4)) % 4)
    try:
        decoded = base64.urlsafe_b64decode((raw + pad).encode("ascii"))
        return json.loads(decoded.decode("utf-8"))
    except Exception:
        return {}


def extract_workspaces_from_auth_cookie(auth_cookie: str) -> List[Dict[str, Any]]:
    """从 oai-client-auth-session Cookie 中提取 workspace 列表。"""
    raw = str(auth_cookie or "").strip()
    if not raw:
        return []

    candidates = [raw]
    if "." in raw:
        candidates.extend(part for part in raw.split(".") if part)

    seen_candidates: Set[str] = set()
    for candidate in candidates:
        if candidate in seen_candidates:
            continue
        seen_candidates.add(candidate)

        data = _decode_jwt_segment(candidate)
        if not isinstance(data, dict) or not data:
            continue

        nodes = [
            data,
            data.get("session"),
            data.get("user"),
            data.get("payload"),
            data.get("claims"),
        ]
        for node in nodes:
            if not isinstance(node, dict):
                continue
            workspaces = node.get("workspaces") or []
            if isinstance(workspaces, list) and workspaces:
                return [item for item in workspaces if isinstance(item, dict)]

    return []


def _to_int(v: Any) -> int:
    """安全地将值转为整数。"""
    try:
        return int(v)
    except (TypeError, ValueError):
        return 0


# ---------------------------------------------------------------------------
# HTTP 表单提交工具
# ---------------------------------------------------------------------------


def _post_form(
    url: str,
    data: Dict[str, str],
    timeout: int = 30,
    proxies: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """向指定 URL 提交表单（application/x-www-form-urlencoded）。"""
    response = requests.post(
        url,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
            "sec-ch-ua": '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
            "sec-ch-ua-mobile": "?0",
            "sec-ch-ua-platform": '"Windows"',
        },
        data=data,
        proxies=proxies,
        timeout=timeout,
        impersonate="chrome120",
    )
    if response.status_code != 200:
        raise RuntimeError(
            f"token exchange failed: {response.status_code}: {response.text}"
        )
    return response.json()


# ---------------------------------------------------------------------------
# OAuth 授权 URL 构建
# ---------------------------------------------------------------------------


def build_oauth_authorize_url(
    *,
    state: str,
    code_verifier: str,
    redirect_uri: str,
    scope: str,
    prompt: Optional[str] = "login",
) -> str:
    """构建 OpenAI OAuth 授权 URL。"""
    params = {
        "client_id": CLIENT_ID,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
        "code_challenge": _sha256_b64url_no_pad(code_verifier),
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
    }
    prompt_value = None if prompt is None else str(prompt).strip()
    if prompt_value:
        params["prompt"] = prompt_value
    return f"{AUTH_URL}?{urllib.parse.urlencode(params)}"


def oauth_authorize_url(oauth: OAuthStart, *, prompt: Optional[str] = "login") -> str:
    """基于 OAuthStart 参数构建授权 URL。"""
    return build_oauth_authorize_url(
        state=oauth.state,
        code_verifier=oauth.code_verifier,
        redirect_uri=oauth.redirect_uri,
        scope=oauth.scope,
        prompt=prompt,
    )


def generate_oauth_url(
    *, redirect_uri: str = DEFAULT_REDIRECT_URI, scope: str = DEFAULT_SCOPE
) -> OAuthStart:
    """生成一组全新的 OAuth 授权参数（含 PKCE）。"""
    state = _random_state()
    code_verifier = _pkce_verifier()
    auth_url = build_oauth_authorize_url(
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        scope=scope,
        prompt="login",
    )
    return OAuthStart(
        auth_url=auth_url,
        state=state,
        code_verifier=code_verifier,
        redirect_uri=redirect_uri,
        scope=scope,
    )


# ---------------------------------------------------------------------------
# Web Signup 入口
# ---------------------------------------------------------------------------


def bootstrap_web_signup_start_url(session: Any, thread_id: int) -> str:
    """通过 ChatGPT Web 入口获取 OAuth 授权起始 URL。"""
    attempts = max(1, WEB_SIGNUP_MAX_ATTEMPTS)
    for attempt in range(1, attempts + 1):
        try:
            csrf_resp = session.get(
                "https://chatgpt.com/api/auth/csrf",
                headers={"referer": WEB_SIGNIN_REFERER, "accept": "application/json"},
                timeout=WEB_SIGNUP_REQUEST_TIMEOUT_SECONDS,
            )
            if csrf_resp.status_code != 200:
                diagnostics = _response_diagnostics(
                    csrf_resp,
                    thread_id=thread_id,
                    label="web_signup_csrf",
                )
                setattr(
                    session,
                    "_last_web_signup_failure_detail",
                    f"csrf status={csrf_resp.status_code} {diagnostics}",
                )
                logger.error(
                    f"[线程 {thread_id}] [错误] 获取 web signup csrf 失败，状态码: {csrf_resp.status_code}"
                )
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            csrf_token = str((csrf_resp.json() or {}).get("csrfToken") or "").strip()
            if not csrf_token:
                diagnostics = _response_diagnostics(
                    csrf_resp,
                    thread_id=thread_id,
                    label="web_signup_csrf_empty",
                )
                setattr(
                    session,
                    "_last_web_signup_failure_detail",
                    f"csrf token missing {diagnostics}",
                )
                logger.error(
                    f"[线程 {thread_id}] [错误] web signup csrfToken 为空"
                )
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            ext_oai_did = str(uuid.uuid4())
            auth_session_logging_id = str(uuid.uuid4())
            query = urllib.parse.urlencode(
                {
                    "prompt": "login",
                    "screen_hint": "login_or_signup",
                    "ext-oai-did": ext_oai_did,
                    "auth_session_logging_id": auth_session_logging_id,
                }
            )
            signin_resp = session.post(
                f"https://chatgpt.com/api/auth/signin/openai?{query}",
                headers={
                    "referer": WEB_SIGNIN_REFERER,
                    "accept": "application/json",
                    "content-type": "application/x-www-form-urlencoded",
                },
                data=urllib.parse.urlencode(
                    {
                        "callbackUrl": "/",
                        "csrfToken": csrf_token,
                        "json": "true",
                    }
                ),
                timeout=WEB_SIGNUP_REQUEST_TIMEOUT_SECONDS,
            )
            if signin_resp.status_code != 200:
                diagnostics = _response_diagnostics(
                    signin_resp,
                    thread_id=thread_id,
                    label="web_signup_signin_openai",
                )
                setattr(
                    session,
                    "_last_web_signup_failure_detail",
                    f"signin/openai status={signin_resp.status_code} {diagnostics}",
                )
                logger.error(
                    f"[线程 {thread_id}] [错误] web signup signin/openai 失败，状态码: {signin_resp.status_code}"
                )
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            start_url = str((signin_resp.json() or {}).get("url") or "").strip()
            if not start_url:
                diagnostics = _response_diagnostics(
                    signin_resp,
                    thread_id=thread_id,
                    label="web_signup_signin_openai_missing_url",
                )
                setattr(
                    session,
                    "_last_web_signup_failure_detail",
                    f"signin/openai missing url {diagnostics}",
                )
                logger.error(
                    f"[线程 {thread_id}] [错误] web signup 未返回授权地址"
                )
                if attempt < attempts:
                    time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue

            setattr(session, "_last_web_signup_failure_detail", "")
            logger.info(f"[线程 {thread_id}] [信息] 已获取 web signup 授权入口")
            return start_url
        except Exception as exc:
            if attempt < attempts:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 获取 web signup 授权入口失败，第 {attempt}/{attempts} 次尝试异常: {exc}；"
                    f"{WEB_SIGNUP_RETRY_DELAY_SECONDS} 秒后重试"
                )
                time.sleep(WEB_SIGNUP_RETRY_DELAY_SECONDS)
                continue
            logger.error(f"[线程 {thread_id}] [错误] 获取 web signup 授权入口失败: {exc}")
            return ""

    return ""


# ---------------------------------------------------------------------------
# 回调 URL 提交与 Token 交换
# ---------------------------------------------------------------------------


def submit_callback_url(
    *,
    callback_url: str,
    expected_state: str,
    code_verifier: str,
    redirect_uri: str = DEFAULT_REDIRECT_URI,
) -> str:
    """解析回调 URL 并用 authorization_code 换取 token。"""
    cb = _parse_callback_url(callback_url)
    if cb["error"]:
        desc = cb["error_description"]
        raise RuntimeError(f"oauth error: {cb['error']}: {desc}".strip())

    if not cb["code"]:
        raise ValueError("callback url missing ?code=")
    if not cb["state"]:
        raise ValueError("callback url missing ?state=")
    if cb["state"] != expected_state:
        raise ValueError("state mismatch")

    token_resp = _post_form(
        TOKEN_URL,
        {
            "grant_type": "authorization_code",
            "client_id": CLIENT_ID,
            "code": cb["code"],
            "redirect_uri": redirect_uri,
            "code_verifier": code_verifier,
        },
    )

    access_token = (token_resp.get("access_token") or "").strip()
    refresh_token = (token_resp.get("refresh_token") or "").strip()
    id_token = (token_resp.get("id_token") or "").strip()
    expires_in = _to_int(token_resp.get("expires_in"))

    claims = _jwt_claims_no_verify(id_token)
    email = str(claims.get("email") or "").strip()
    auth_claims = claims.get("https://api.openai.com/auth") or {}
    account_id = str(auth_claims.get("chatgpt_account_id") or "").strip()

    now = int(time.time())
    expired_rfc3339 = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(now + max(expires_in, 0))
    )
    now_rfc3339 = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))

    config = {
        "id_token": id_token,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "account_id": account_id,
        "last_refresh": now_rfc3339,
        "email": email,
        "type": "codex",
        "expired": expired_rfc3339,
    }

    return json.dumps(config, ensure_ascii=False, separators=(",", ":"))


# ---------------------------------------------------------------------------
# 响应解析工具
# ---------------------------------------------------------------------------


def extract_continue_url_from_response(resp: Any) -> str:
    """从 HTTP 响应中提取 continue/redirect URL。"""
    base_url = str(getattr(resp, "url", "") or AUTH_URL).strip() or AUTH_URL
    headers = getattr(resp, "headers", {}) or {}

    location = str(headers.get("Location") or "").strip()
    if location:
        return urllib.parse.urljoin(base_url, location)

    try:
        payload = resp.json() if getattr(resp, "content", b"") else {}
    except Exception:
        payload = {}

    if isinstance(payload, dict):
        for key in ("continue_url", "redirect_url", "next_url", "url"):
            candidate = str(payload.get(key) or "").strip()
            if candidate:
                return urllib.parse.urljoin(base_url, candidate)

    text = str(getattr(resp, "text", "") or "")
    if not text:
        return ""

    json_like_match = re.search(
        r'"(?:continue_url|redirect_url|next_url|url)"\s*:\s*"([^"]+)"', text
    )
    if json_like_match:
        candidate = json_like_match.group(1).replace("\\/", "/").strip()
        if candidate:
            return urllib.parse.urljoin(base_url, candidate)

    callback_match = re.search(
        r"(http://localhost:1455/auth/callback[^\"'\s<>]+)", text
    )
    if callback_match:
        return callback_match.group(1).strip()

    return ""


def response_text_preview(resp: Any, limit: int = 240) -> str:
    """获取 HTTP 响应文本的简短预览。"""
    text = str(getattr(resp, "text", "") or "").strip()
    if not text:
        return ""
    compact = re.sub(r"\s+", " ", text)
    if len(compact) <= limit:
        return compact
    return compact[: limit - 3] + "..."


def _response_header_value(resp: Any, key: str) -> str:
    headers = getattr(resp, "headers", None)
    if not headers:
        return ""
    try:
        value = headers.get(key)
        if value:
            return str(value).strip()
    except Exception:
        pass
    try:
        for header_key, header_value in headers.items():
            if str(header_key).strip().lower() == key.lower():
                return str(header_value).strip()
    except Exception:
        pass
    return ""


def _html_title_from_response(resp: Any) -> str:
    text = str(getattr(resp, "text", "") or "")
    if not text:
        return ""
    matched = re.search(r"<title[^>]*>(.*?)</title>", text, flags=re.I | re.S)
    if not matched:
        return ""
    title = re.sub(r"\s+", " ", matched.group(1)).strip()
    return html.unescape(title)


def _dump_response_html(resp: Any, *, thread_id: int, label: str) -> str:
    text = str(getattr(resp, "text", "") or "")
    if not text:
        return ""
    content_type = _response_header_value(resp, "content-type").lower()
    looks_html = "text/html" in content_type or "<html" in text.lower()
    if not looks_html:
        return ""
    try:
        os.makedirs(_DEBUG_DIR, exist_ok=True)
        safe_label = re.sub(r"[^0-9a-zA-Z._-]+", "_", str(label or "response")).strip("._") or "response"
        filename = f"{safe_label}.t{int(thread_id)}.{int(time.time() * 1000)}.html"
        path = os.path.join(_DEBUG_DIR, filename)
        with open(path, "w", encoding="utf-8") as file_obj:
            file_obj.write(text[:2_000_000])
        return path
    except Exception:
        return ""


def _response_diagnostics(resp: Any, *, thread_id: int, label: str) -> str:
    preview = response_text_preview(resp, limit=220) or "(empty)"
    final_url = str(getattr(resp, "url", "") or "").strip()
    content_type = _response_header_value(resp, "content-type")
    server = _response_header_value(resp, "server")
    cf_ray = _response_header_value(resp, "cf-ray")
    x_vercel_id = _response_header_value(resp, "x-vercel-id")
    location = _response_header_value(resp, "location")
    title = _html_title_from_response(resp)
    dump_path = _dump_response_html(resp, thread_id=thread_id, label=label)
    parts = [f"final_url={final_url or '(unknown)'}"]
    if content_type:
        parts.append(f"content_type={content_type}")
    if server:
        parts.append(f"server={server}")
    if cf_ray:
        parts.append(f"cf_ray={cf_ray}")
    if x_vercel_id:
        parts.append(f"x_vercel_id={x_vercel_id}")
    if location:
        parts.append(f"location={location}")
    if title:
        parts.append(f"title={title}")
    if dump_path:
        parts.append(f"html_dump={dump_path}")
    parts.append(f"preview={preview}")
    return "，".join(parts)


def _parse_json_object(raw_text: str) -> Dict[str, Any]:
    """从文本中尝试解析 JSON 对象。"""
    content = str(raw_text or "").strip()
    if not content:
        return {}

    candidates = [content]
    match = re.search(r"\{.*\}", content, re.S)
    if match:
        candidates.append(match.group(0))

    seen: Set[str] = set()
    for candidate in candidates:
        candidate = str(candidate or "").strip()
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        try:
            payload = json.loads(candidate)
        except Exception:
            continue
        if isinstance(payload, dict):
            return payload

    return {}


def _session_fallback_expired_at(payload: Dict[str, Any]) -> str:
    """获取 session 兜底的过期时间。"""
    expires = str(payload.get("expires") or "").strip()
    if expires:
        return expires

    return time.strftime(
        "%Y-%m-%dT%H:%M:%SZ",
        time.gmtime(time.time() + DEFAULT_SESSION_FALLBACK_EXPIRES_IN_SECONDS),
    )


# ---------------------------------------------------------------------------
# Email OTP 校验
# ---------------------------------------------------------------------------


def post_email_otp_validate(
    session: Any,
    *,
    code: str,
    thread_id: int,
    stage_label: str,
    max_attempts: int = EMAIL_OTP_VALIDATE_MAX_ATTEMPTS,
    retry_delay_seconds: int = EMAIL_OTP_VALIDATE_RETRY_DELAY_SECONDS,
) -> Optional[Any]:
    """向 OpenAI 提交邮箱验证码校验请求（带重试）。"""
    payload = json.dumps(
        {"code": str(code or "").strip()},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    attempts = max(1, max_attempts)
    delay_seconds = max(0, int(retry_delay_seconds))
    last_resp = None

    for attempt in range(1, attempts + 1):
        try:
            last_resp = session.post(
                "https://auth.openai.com/api/accounts/email-otp/validate",
                headers={
                    "referer": "https://auth.openai.com/email-verification",
                    "accept": "application/json",
                    "content-type": "application/json",
                },
                data=payload,
            )
        except Exception as exc:
            if attempt < attempts:
                logger.warning(
                    f"[线程 {thread_id}] [警告] {stage_label}邮箱验证码校验异常，"
                    f"第 {attempt}/{attempts} 次尝试失败: {exc}；"
                    f"{delay_seconds} 秒后重试"
                )
                time.sleep(delay_seconds)
                continue
            logger.error(f"[线程 {thread_id}] [错误] {stage_label}邮箱验证码校验异常: {exc}")
            return None

        status_code = getattr(last_resp, "status_code", 0)
        if status_code == 200:
            return last_resp

        if status_code in RETRYABLE_GATEWAY_STATUSES and attempt < attempts:
            preview = response_text_preview(last_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] {stage_label}邮箱验证码校验遇到网关波动，"
                f"状态码: {status_code}，第 {attempt}/{attempts} 次尝试；"
                f"{delay_seconds} 秒后重试。响应摘要: {preview}"
            )
            time.sleep(delay_seconds)
            continue

        return last_resp

    return last_resp


# ---------------------------------------------------------------------------
# OAuth 重定向链跟随
# ---------------------------------------------------------------------------


def follow_oauth_redirect_chain(
    session: Any,
    start_url: str,
    oauth: OAuthStart,
    thread_id: int,
    *,
    max_hops: int = 8,
) -> Optional[str]:
    """跟随 OAuth 重定向链直到拿到 callback URL 并兑换 token。"""
    current_url = str(start_url or "").strip()
    if not current_url:
        return None

    try:
        for _ in range(max_hops):
            if "code=" in current_url and "state=" in current_url:
                parsed_current = urllib.parse.urlparse(current_url)
                if parsed_current.hostname in ("localhost", "127.0.0.1"):
                    return submit_callback_url(
                        callback_url=current_url,
                        code_verifier=oauth.code_verifier,
                        redirect_uri=oauth.redirect_uri,
                        expected_state=oauth.state,
                    )
                if parsed_current.hostname in ("chatgpt.com", "www.chatgpt.com"):
                    logger.info(
                        f"[线程 {thread_id}] [信息] OAuth 跳转链命中 ChatGPT Web callback，先消费 Web callback 再交给上层提 token"
                    )
                    session.get(current_url, allow_redirects=True, timeout=15)
                    return None

            resp = session.get(current_url, allow_redirects=False, timeout=15)
            next_url = extract_continue_url_from_response(resp)
            if not next_url:
                break
            if "code=" in next_url and "state=" in next_url:
                parsed_next = urllib.parse.urlparse(next_url)
                if parsed_next.hostname in ("localhost", "127.0.0.1"):
                    return submit_callback_url(
                        callback_url=next_url,
                        code_verifier=oauth.code_verifier,
                        redirect_uri=oauth.redirect_uri,
                        expected_state=oauth.state,
                    )
                if parsed_next.hostname in ("chatgpt.com", "www.chatgpt.com"):
                    logger.info(
                        f"[线程 {thread_id}] [信息] OAuth 跳转链命中 ChatGPT Web callback，先消费 Web callback 再交给上层提 token"
                    )
                    session.get(next_url, allow_redirects=True, timeout=15)
                    return None
            if next_url == current_url:
                break
            current_url = next_url
    except Exception as exc:
        callback_match = re.search(
            r"(http://localhost:1455/auth/callback[^\"'\s<>]+)",
            str(exc or ""),
        )
        if callback_match:
            return submit_callback_url(
                callback_url=callback_match.group(1).strip(),
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
                expected_state=oauth.state,
            )
        logger.warning(f"[线程 {thread_id}] [警告] 跟随 OAuth 跳转链失败: {exc}")

    return None


# ---------------------------------------------------------------------------
# OAuth Session 初始化
# ---------------------------------------------------------------------------


def prime_oauth_session(
    session: Any,
    start_url: str,
    thread_id: int,
    *,
    max_hops: int = 6,
) -> Any:
    """初始化 OAuth session，跟随重定向直到停止或遇到本地 callback。"""
    current_url = str(start_url or "").strip()
    last_resp = None
    if not current_url:
        return None

    for _ in range(max_hops):
        last_exc = None
        for attempt in range(1, PRIME_OAUTH_MAX_REQUEST_ATTEMPTS + 1):
            try:
                last_resp = session.get(
                    current_url,
                    timeout=PRIME_OAUTH_REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=False,
                )
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                if attempt < PRIME_OAUTH_MAX_REQUEST_ATTEMPTS:
                    logger.warning(
                        f"[线程 {thread_id}] [警告] OAuth 初始化请求失败，第 {attempt}/{PRIME_OAUTH_MAX_REQUEST_ATTEMPTS} 次重试: {exc}"
                    )
                    time.sleep(PRIME_OAUTH_RETRY_DELAY_SECONDS)
        if last_exc is not None:
            raise last_exc

        next_url = extract_continue_url_from_response(last_resp)
        if not next_url:
            return last_resp

        parsed = urllib.parse.urlparse(next_url)
        if (
            parsed.scheme == "http"
            and parsed.hostname in ("localhost", "127.0.0.1")
            and "/auth/callback" in parsed.path
        ):
            logger.info(
                f"[线程 {thread_id}] [信息] OAuth 初始化已到达本地 callback 边界，停止继续自动跳转"
            )
            return last_resp

        current_url = next_url

    return last_resp
