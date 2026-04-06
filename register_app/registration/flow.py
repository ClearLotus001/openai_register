# -*- coding: utf-8 -*-
"""核心注册流程与单 provider 注册入口。"""
from __future__ import annotations

import builtins
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

from curl_cffi import requests

from ..browser import is_roxy_configured
from ..browser.runtime import get_browser_runtime_config
from ..auth.browser_oauth import try_browser_oauth_password_login
from ..auth.oauth import (
    bootstrap_web_signup_start_url,
    extract_continue_url_from_response,
    generate_oauth_url,
    post_email_otp_validate,
    prime_oauth_session,
    response_text_preview,
)
from ..mail.cfmail import (
    record_cfmail_failure as _record_cfmail_failure,
    record_cfmail_success as _record_cfmail_success,
    reload_cfmail_accounts_if_needed as _reload_cfmail_accounts_if_needed,
)
from ..mail.dedupe import get_mailbox_dedupe_store
from ..config import DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS
from ..mail.providers import TempMailbox
from ..sentinel import random_impersonate, request_sentinel_header
from ..auth.token import (
    try_token_via_continue_url,
    try_token_via_existing_session,
    try_token_via_password_login,
    try_token_via_session_api,
    try_token_via_session_cookie,
    try_token_via_workspace_select,
)
from .common import (
    RegistrationAttemptResult,
    _accept_codex_token,
    _build_random_signup_profile,
    _build_request_proxies,
    _enrich_token_json,
    _extract_response_error_code_message,
    _generate_password,
    _is_invalid_auth_step,
    _mailbox_public_metadata,
    _mailbox_wait_failure_reason,
    _post_create_account_with_retry,
    _post_user_register_with_fallback,
    _preview_response_text,
    _response_json_object,
)
from .mailbox import (
    get_mailbox_message_snapshot,
    get_oai_code,
    get_temp_mailbox,
)
from .browser_flow import run_browser as _run_browser

logger = logging.getLogger("openai_register")
_BROWSER_ENGINE_PHASE1_WARNED = False


def _mailbox_private_context(mailbox: TempMailbox) -> Dict[str, Any]:
    return {
        "email": str(mailbox.email or "").strip(),
        "provider": str(mailbox.provider or "").strip(),
        "token": str(mailbox.token or "").strip(),
        "api_base": str(mailbox.api_base or "").strip(),
        "login": str(mailbox.login or "").strip(),
        "domain": str(mailbox.domain or "").strip(),
        "sid_token": str(mailbox.sid_token or "").strip(),
        "password": str(mailbox.password or "").strip(),
        "config_name": str(mailbox.config_name or "").strip(),
    }


def _mailbox_from_private_context(
    mailbox_context: Optional[Dict[str, Any]],
    *,
    fallback_email: str,
    fallback_provider: str,
) -> TempMailbox:
    context = mailbox_context or {}
    return TempMailbox(
        email=str(context.get("email") or fallback_email or "").strip(),
        provider=str(context.get("provider") or fallback_provider or "").strip(),
        token=str(context.get("token") or "").strip(),
        api_base=str(context.get("api_base") or "").strip(),
        login=str(context.get("login") or "").strip(),
        domain=str(context.get("domain") or "").strip(),
        sid_token=str(context.get("sid_token") or "").strip(),
        password=str(context.get("password") or "").strip(),
        config_name=str(context.get("config_name") or "").strip(),
    )


def _should_try_browser_oauth_fallback(
    attempt: RegistrationAttemptResult,
    requested_engine: str,
) -> bool:
    if attempt.success:
        return False
    if requested_engine not in {"browser", "hybrid"}:
        return False
    if str(attempt.error_code or "").strip() != "token_extraction_failed":
        return False
    if not str(attempt.email or "").strip() or not str(attempt.password or "").strip():
        return False
    mailbox_context = attempt.private_context.get("mailbox") if isinstance(attempt.private_context, dict) else None
    return isinstance(mailbox_context, dict) and bool(mailbox_context.get("email"))

# ---------------------------------------------------------------------------
# 核心注册主流程
# ---------------------------------------------------------------------------

def _run_http(
    proxy: Optional[str], provider_key: str, thread_id: int, mailtm_base: str
) -> RegistrationAttemptResult:
    """注册主流程。

    1. 检测出口 / 代理
    2. 创建临时邮箱（含去重）
    3. OpenAI 注册 / 已有账号 OTP 校验
    4. 多策略提取 token，并补充丰富元数据
    """
    result = RegistrationAttemptResult(
        provider_key=str(provider_key or "").strip().lower(),
        metadata={"thread_id": thread_id},
    )

    def _set_stage(stage: str, **metadata: Any) -> None:
        result.stage = stage
        if metadata:
            result.metadata.update(metadata)

    def _fail(
        stage: str,
        error_code: str,
        error_message: str,
        *,
        affect_cooldown: bool = False,
        cfmail_reason: Optional[str] = None,
        **metadata: Any,
    ) -> RegistrationAttemptResult:
        _set_stage(stage, **metadata)
        result.success = False
        result.error_code = str(error_code or "").strip()
        result.error_message = str(error_message or "").strip()
        if affect_cooldown:
            _mark_cfmail_failure(
                cfmail_reason or f"{result.error_code or 'failed'}: {result.error_message}",
                affect_cooldown=True,
            )
        return result

    def _resp_detail(resp: Any, limit: int = 500) -> str:
        return _preview_response_text(resp, limit=limit) or "(empty)"

    if provider_key == "cfmail":
        _reload_cfmail_accounts_if_needed()

    proxies: Any = _build_request_proxies(proxy)
    cfmail_config_name = ""
    mailbox_dedupe_store = get_mailbox_dedupe_store()
    reserved_mailbox_email = ""

    def _mark_cfmail_failure(reason: str, *, affect_cooldown: bool = False) -> None:
        if provider_key == "cfmail" and cfmail_config_name and affect_cooldown:
            _record_cfmail_failure(cfmail_config_name, reason)

    def _mark_cfmail_success() -> None:
        if provider_key == "cfmail" and cfmail_config_name:
            _record_cfmail_success(cfmail_config_name)

    current_impersonate = random_impersonate()
    logger.info(f"[线程 {thread_id}] [信息] 当前浏览器指纹: {current_impersonate}")
    result.metadata["impersonate"] = current_impersonate
    result.metadata["registration_proxy_url"] = str(proxy or "").strip()

    s = requests.Session(proxies=proxies, impersonate=current_impersonate)
    mailbox: Optional[TempMailbox] = None

    try:
        _set_stage("network_check")
        trace = s.get("https://cloudflare.com/cdn-cgi/trace", timeout=10).text
        loc_re = re.search(r"^loc=(.+)$", trace, re.MULTILINE)
        loc = loc_re.group(1) if loc_re else None
        logger.info(f"[线程 {thread_id}] [信息] 当前出口地区: {loc}")
        result.metadata["exit_loc"] = loc
        if loc != "US":
            if not builtins.yasal_bypass_ip_choice:
                return _fail(
                    "network_check",
                    "non_us_exit_blocked",
                    f"当前出口地区 {loc} 不符合要求",
                    exit_loc=loc,
                )
            logger.info(f"[线程 {thread_id}] [信息] 当前节点地区 ({loc}) 不是 US，已默认继续执行")

        if loc in ("CN", "HK"):
            if builtins.yasal_bypass_ip_choice:
                logger.warning(
                    f"[线程 {thread_id}] [警告] 当前地区 {loc} 风险较高，但未显式设置代理；按直连继续执行"
                )
            else:
                return _fail(
                    "network_check",
                    "high_risk_exit",
                    f"当前出口地区 {loc} 风险过高",
                    exit_loc=loc,
                )

        _set_stage("mailbox_create")
        duplicate_count = 0
        for _ in range(5):
            candidate = get_temp_mailbox(
                provider_key,
                thread_id,
                proxies,
                mailtm_base=mailtm_base,
            )
            if not candidate:
                mailbox = None
                break
            if mailbox_dedupe_store.reserve(candidate.email):
                mailbox = candidate
                reserved_mailbox_email = candidate.email
                break
            duplicate_count += 1
            logger.warning(
                f"[线程 {thread_id}] [警告] 当前邮箱 {candidate.email} 已在本地去重名单中，准备重新申请新邮箱"
            )
        if not mailbox:
            return _fail(
                "mailbox_create",
                "mailbox_duplicate_exhausted" if duplicate_count > 0 else "mailbox_unavailable",
                "临时邮箱服务不可用或短时间内重复命中过往邮箱",
                mailbox_duplicate_retries=duplicate_count,
            )

        cfmail_config_name = mailbox.config_name
        email = mailbox.email
        result.email = email
        result.metadata.update(
            {
                "mailbox_provider": mailbox.provider,
                "mailbox_email": email,
                "cfmail_config_name": cfmail_config_name or "",
                "mailbox_metadata": _mailbox_public_metadata(mailbox),
                "mailbox_duplicate_retries": duplicate_count,
            }
        )
        result.private_context["mailbox"] = _mailbox_private_context(mailbox)
        logger.info(f"[线程 {thread_id}] [*] 成功获取临时邮箱与授权: {email} ({mailbox.provider})")

        oauth = generate_oauth_url()
        result.metadata["oauth_redirect_uri"] = oauth.redirect_uri
        password = _generate_password()
        result.password = password

        def _bootstrap_signup_context(*, reset_reason: str = "") -> Tuple[str, str, str]:
            _set_stage("signup_start", auth_reset_reason=reset_reason or "")
            signup_start_url = bootstrap_web_signup_start_url(s, thread_id)
            if not signup_start_url:
                return "", "", ""
            _set_stage("oauth_prime", signup_start_url=signup_start_url, auth_reset_reason=reset_reason or "")
            prime_oauth_session(s, signup_start_url, thread_id)
            did = str(s.cookies.get("oai-did") or "").strip()
            result.metadata["device_id"] = did
            if not did:
                return signup_start_url, "", ""
            sentinel = request_sentinel_header(
                did=did,
                proxies=proxies,
                impersonate=current_impersonate,
                thread_id=thread_id,
            )
            return signup_start_url, did, sentinel

        def _submit_signup(sentinel_token: str) -> Any:
            signup_body = json.dumps(
                {
                    "username": {"value": email, "kind": "email"},
                    "screen_hint": "login_or_signup",
                },
                ensure_ascii=False,
                separators=(",", ":"),
            )
            _set_stage("authorize_continue")
            signup_resp = s.post(
                "https://auth.openai.com/api/accounts/authorize/continue",
                headers={
                    "referer": "https://auth.openai.com/log-in-or-create-account",
                    "accept": "application/json",
                    "content-type": "application/json",
                    "openai-sentinel-token": sentinel_token,
                },
                data=signup_body,
            )
            logger.info(f"[线程 {thread_id}] [信息] 注册表单已提交，状态码: {signup_resp.status_code}")
            return signup_resp

        signup_start_url, did, sentinel = _bootstrap_signup_context()
        if not signup_start_url:
            signup_debug = str(getattr(s, "_last_web_signup_failure_detail", "") or "").strip()
            return _fail(
                "signup_start",
                "signup_start_url_missing",
                "未获取到 web signup 授权入口",
                failure_detail=signup_debug,
            )
        if not did:
            return _fail("oauth_prime", "device_id_missing", "OAuth 初始化后未获取到 device id")
        if not sentinel:
            return _fail("authorize_continue", "sentinel_token_missing", "未获取到 openai-sentinel-token")

        signup_resp = _submit_signup(sentinel)
        if signup_resp.status_code in (403, 429):
            signup_error_preview = _preview_response_text(signup_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] 注册表单失败：status={signup_resp.status_code}"
            )
            return _fail(
                "authorize_continue",
                f"authorize_continue_{signup_resp.status_code}",
                signup_error_preview,
                status_code=signup_resp.status_code,
                failure_detail=signup_error_preview,
            )
        if signup_resp.status_code != 200 and _is_invalid_auth_step(signup_resp):
            logger.info(f"[线程 {thread_id}] [信息] signup 遇到 invalid_auth_step，重建认证上下文后重试一次")
            s = requests.Session(proxies=proxies, impersonate=current_impersonate)
            signup_start_url, did, sentinel = _bootstrap_signup_context(reset_reason="invalid_auth_step")
            if not signup_start_url:
                signup_debug = str(getattr(s, "_last_web_signup_failure_detail", "") or "").strip()
                return _fail(
                    "signup_start",
                    "signup_start_url_missing",
                    "重试时未获取到 web signup 授权入口",
                    failure_detail=signup_debug,
                )
            if not did:
                return _fail("oauth_prime", "device_id_missing", "重试时未获取到 device id")
            if not sentinel:
                return _fail("authorize_continue", "sentinel_token_missing", "重试时未获取到 openai-sentinel-token")
            signup_resp = _submit_signup(sentinel)

        if signup_resp.status_code != 200:
            signup_error_code, signup_error_message = _extract_response_error_code_message(signup_resp)
            signup_detail = signup_error_message or _preview_response_text(signup_resp)
            logger.warning(
                f"[线程 {thread_id}] [警告] 注册表单失败：status={signup_resp.status_code}，"
                f"code={signup_error_code or 'unknown'}"
            )
            return _fail(
                "authorize_continue",
                signup_error_code or f"authorize_continue_{signup_resp.status_code}",
                signup_detail,
                status_code=signup_resp.status_code,
                signup_error_code=signup_error_code,
                signup_error_message=signup_error_message,
                failure_detail=signup_detail,
            )

        signup_payload = _response_json_object(signup_resp)
        signup_page = signup_payload.get("page") if isinstance(signup_payload.get("page"), dict) else {}
        signup_page_type = str((signup_page or {}).get("type") or "").strip()
        signup_continue_url = extract_continue_url_from_response(signup_resp)
        is_existing_account = signup_page_type == "email_otp_verification"
        result.metadata.update(
            {
                "signup_page_type": signup_page_type,
                "signup_continue_url": signup_continue_url,
                "is_existing_account": is_existing_account,
            }
        )

        existing_signup_message_ids: Set[str] = set()
        code = ""
        otp_send_url = ""
        if is_existing_account:
            logger.info(f"[线程 {thread_id}] [信息] 当前邮箱疑似已存在账号，跳过密码注册与验证码发送，直接进入邮箱验证码校验")
        else:
            existing_signup_message_ids = get_mailbox_message_snapshot(mailbox, thread_id, proxies)
            _set_stage("password_register")
            register_resp, register_meta = _post_user_register_with_fallback(
                s,
                username=email,
                password=password,
                did=did,
                proxies=proxies,
                impersonate=current_impersonate,
                thread_id=thread_id,
            )
            result.metadata.update(register_meta)
            logger.info(f"[线程 {thread_id}] [信息] 密码注册请求已提交，状态码: {register_resp.status_code}")
            if register_resp.status_code != 200:
                register_error_code, register_error_message = _extract_response_error_code_message(register_resp)
                register_detail = register_error_message or _resp_detail(register_resp, limit=800)
                logger.warning(
                    f"[线程 {thread_id}] [警告] 密码注册失败：status={register_resp.status_code}，"
                    f"code={register_error_code or 'unknown'}"
                )
                return _fail(
                    "password_register",
                    register_error_code or f"user_register_{register_resp.status_code}",
                    register_detail,
                    status_code=register_resp.status_code,
                    register_error_code=register_error_code,
                    register_error_message=register_error_message,
                    failure_detail=register_detail,
                )

            register_payload = _response_json_object(register_resp)
            register_page = register_payload.get("page") if isinstance(register_payload.get("page"), dict) else {}
            register_page_type = str((register_page or {}).get("type") or "").strip()
            register_continue_url = extract_continue_url_from_response(register_resp)
            result.metadata.update(
                {
                    "password_register_page_type": register_page_type,
                    "password_register_continue_url": register_continue_url,
                }
            )

            _set_stage("email_otp_send")
            otp_send_url = register_continue_url or "https://auth.openai.com/api/accounts/email-otp/send"
            otp_resp = s.get(
                otp_send_url,
                headers={
                    "referer": "https://auth.openai.com/create-account/password",
                    "accept": "application/json",
                },
            )
            logger.info(f"[线程 {thread_id}] [信息] 注册阶段验证码发送请求已提交，状态码: {otp_resp.status_code}")
            if otp_resp.status_code != 200:
                otp_error_code, otp_error_message = _extract_response_error_code_message(otp_resp)
                otp_detail = otp_error_message or _resp_detail(otp_resp, limit=800)
                logger.warning(
                    f"[线程 {thread_id}] [警告] 注册阶段验证码发送失败：status={otp_resp.status_code}，"
                    f"code={otp_error_code or 'unknown'}"
                )
                return _fail(
                    "email_otp_send",
                    otp_error_code or f"email_otp_send_{otp_resp.status_code}",
                    otp_detail,
                    status_code=otp_resp.status_code,
                    otp_error_code=otp_error_code,
                    otp_error_message=otp_error_message,
                    failure_detail=otp_detail,
                )

        seen_signup_message_ids: Set[str] = set(existing_signup_message_ids)
        signup_otp_attempts = 1 if is_existing_account else 2
        for otp_attempt in range(1, signup_otp_attempts + 1):
            _set_stage("email_otp_wait", email_otp_attempt=otp_attempt)
            code = get_oai_code(
                mailbox,
                thread_id,
                proxies,
                skip_message_ids=seen_signup_message_ids,
            )
            wait_reason, wait_diagnostics = _mailbox_wait_failure_reason(mailbox)
            if wait_diagnostics:
                result.metadata["otp_wait_diagnostics"] = wait_diagnostics
            if code:
                break

            if otp_attempt >= signup_otp_attempts or not otp_send_url:
                return _fail(
                    "email_otp_wait",
                    wait_reason,
                    "未获取到注册阶段验证码",
                    affect_cooldown=True,
                    cfmail_reason=wait_reason,
                    otp_wait_diagnostics=wait_diagnostics,
                )

            try:
                seen_signup_message_ids.update(
                    get_mailbox_message_snapshot(mailbox, thread_id, proxies)
                )
            except Exception:
                pass

            logger.warning(
                f"[线程 {thread_id}] [警告] 注册阶段等待验证码超时，准备第 {otp_attempt + 1}/{signup_otp_attempts} 次重新触发发送"
            )
            _set_stage("email_otp_resend", email_otp_attempt=otp_attempt + 1)
            otp_resp = s.get(
                otp_send_url,
                headers={
                    "referer": "https://auth.openai.com/create-account/password",
                    "accept": "application/json",
                },
            )
            logger.info(
                f"[线程 {thread_id}] [信息] 注册阶段验证码重发请求已提交，状态码: {otp_resp.status_code}"
            )
            if otp_resp.status_code != 200:
                otp_error_code, otp_error_message = _extract_response_error_code_message(otp_resp)
                otp_detail = otp_error_message or _resp_detail(otp_resp, limit=800)
                return _fail(
                    "email_otp_resend",
                    otp_error_code or f"email_otp_resend_{otp_resp.status_code}",
                    otp_detail or "注册阶段邮箱验证码重发失败",
                    status_code=otp_resp.status_code,
                    otp_error_code=otp_error_code,
                    otp_error_message=otp_error_message,
                    failure_detail=otp_detail,
                )

        _set_stage("email_otp_validate")
        code_resp = post_email_otp_validate(
            s,
            code=code,
            thread_id=thread_id,
            stage_label="注册阶段",
        )
        logger.info(f"[线程 {thread_id}] [信息] 验证码校验结果状态码: {getattr(code_resp, 'status_code', 'unknown')}")
        if not code_resp or code_resp.status_code != 200:
            preview = response_text_preview(code_resp) if code_resp else ""
            _mark_cfmail_failure(
                f"signup email otp validate status={getattr(code_resp, 'status_code', 'unknown')}",
                affect_cooldown=False,
            )
            return _fail(
                "email_otp_validate",
                f"email_otp_validate_{getattr(code_resp, 'status_code', 'unknown')}",
                preview or "注册阶段邮箱验证码校验失败",
                status_code=getattr(code_resp, "status_code", "unknown"),
            )

        code_payload = _response_json_object(code_resp)
        code_page = code_payload.get("page") if isinstance(code_payload.get("page"), dict) else {}
        code_page_type = str((code_page or {}).get("type") or "").strip()
        code_continue_url = extract_continue_url_from_response(code_resp)
        code_gate = ""
        if "add-phone" in str(code_continue_url or "").lower() or "add_phone" in code_page_type.lower():
            code_gate = "add_phone"
        result.metadata.update(
            {
                "email_otp_validate_page_type": code_page_type,
                "email_otp_validate_continue_url": code_continue_url,
                "email_otp_validate_gate": code_gate,
            }
        )

        post_otp_continue_url = code_continue_url if is_existing_account else ""
        post_create_continue_url = ""
        post_create_gate = ""
        if not is_existing_account:
            signup_profile = _build_random_signup_profile()
            create_account_body = json.dumps(
                signup_profile, ensure_ascii=False, separators=(",", ":")
            )
            _set_stage("create_account", signup_profile=signup_profile)
            logger.info(
                f"[线程 {thread_id}] [信息] 本次注册资料: name={signup_profile['name']}, birthdate={signup_profile['birthdate']}"
            )
            create_account_resp = _post_create_account_with_retry(
                s,
                create_account_body=create_account_body,
                did=did,
                proxies=proxies,
                impersonate=current_impersonate,
                thread_id=thread_id,
            )
            create_account_status = getattr(create_account_resp, "status_code", 0)
            logger.info(f"[线程 {thread_id}] [信息] 创建账户接口状态码: {create_account_status}")

            if not create_account_resp or create_account_status != 200:
                err_code, err_message = _extract_response_error_code_message(create_account_resp)
                err_msg = err_message or _preview_response_text(create_account_resp, limit=1200)
                logger.warning(
                    f"[线程 {thread_id}] [警告] 创建账户失败：status={create_account_status}，"
                    f"code={err_code or 'unknown'}"
                )
                if str(err_code or "").strip().lower() == "user_already_exists":
                    mailbox_dedupe_store.mark(email, reason="user_already_exists")
                if "unsupported_email" in err_msg:
                    logger.info(f"[线程 {thread_id}] [提示] 当前邮箱域名可能被限制，建议更换临时邮箱服务或域名")
                elif "registration_disallowed" in err_msg:
                    logger.info(f"[线程 {thread_id}] [提示] 当前邮箱提供商可能被风控，建议优先使用 tempmaillol")
                elif "429" in str(create_account_status):
                    logger.info(f"[线程 {thread_id}] [提示] 请求频率过高（429），建议更换代理或降低并发")
                _mark_cfmail_failure(
                    f"create_account status={create_account_status} body={err_msg[:120]}",
                    affect_cooldown=(
                        "unsupported_email" in err_msg or "registration_disallowed" in err_msg
                    ),
                )
                return _fail(
                    "create_account",
                    err_code or f"create_account_{create_account_status}",
                    err_msg or "创建账户失败",
                    status_code=create_account_status,
                    create_account_error_code=err_code,
                    create_account_error_message=err_message,
                    failure_detail=err_msg,
                )

            create_account_payload = _response_json_object(create_account_resp)
            post_create_continue_url = extract_continue_url_from_response(create_account_resp)
            create_account_page = create_account_payload.get("page") if isinstance(create_account_payload.get("page"), dict) else {}
            create_account_page_type = str((create_account_page or {}).get("type") or "").strip()
            if "add-phone" in str(post_create_continue_url or "").lower() or "add_phone" in create_account_page_type.lower():
                post_create_gate = "add_phone"
            result.metadata.update(
                {
                    "post_create_continue_url": post_create_continue_url,
                    "post_create_page_type": create_account_page_type,
                    "post_create_gate": post_create_gate,
                }
            )
        else:
            result.metadata.update(
                {
                    "post_create_continue_url": "",
                    "post_create_page_type": "",
                    "post_create_gate": "",
                }
            )

        token_json = None
        token_source = ""

        def _accept_token(candidate: Optional[str], source: str) -> Optional[str]:
            nonlocal token_source
            accepted = _accept_codex_token(
                candidate,
                thread_id=thread_id,
                source=source,
                metadata=result.metadata,
            )
            if accepted:
                token_source = source
            return accepted

        if post_create_continue_url:
            _set_stage("token_continue_url")
            token_json = _accept_token(
                try_token_via_continue_url(
                    s,
                    oauth,
                    post_create_continue_url,
                    thread_id,
                    proxy_url=proxy or "",
                ),
                "create_account_continue",
            )

        if not token_json and post_otp_continue_url:
            _set_stage("token_continue_url_after_otp")
            token_json = _accept_token(
                try_token_via_continue_url(
                    s,
                    oauth,
                    post_otp_continue_url,
                    thread_id,
                    proxy_url=proxy or "",
                ),
                "email_otp_continue",
            )

        if not token_json:
            _set_stage("token_session_cookie")
            token_json = _accept_token(
                try_token_via_session_cookie(s, thread_id, proxy_url=proxy or ""),
                "session_cookie",
            )

        if not token_json:
            _set_stage("token_workspace_select")
            auth_cookie = str(s.cookies.get("oai-client-auth-session") or "").strip()
            token_json = _accept_token(
                try_token_via_workspace_select(
                    s,
                    oauth,
                    auth_cookie,
                    thread_id,
                    proxy_url=proxy or "",
                ),
                "workspace_select",
            )

        if not token_json:
            _set_stage("token_existing_session")
            token_json = _accept_token(
                try_token_via_existing_session(s, oauth, thread_id),
                "existing_session",
            )

        if not token_json:
            _set_stage("token_session_api")
            token_json = _accept_token(
                try_token_via_session_api(s, thread_id),
                "session_api",
            )

        if not token_json:
            _set_stage("token_password_login")
            token_json = _accept_token(
                try_token_via_password_login(
                    email=email,
                    password=password,
                    mailbox=mailbox,
                    used_codes={code} if code else set(),
                    oauth=oauth,
                    proxies=proxies,
                    impersonate=current_impersonate,
                    thread_id=thread_id,
                    get_oai_code_fn=get_oai_code,
                    get_mailbox_message_snapshot_fn=get_mailbox_message_snapshot,
                ),
                "password_login",
            )

        if token_json:
            result.metadata["token_source"] = token_source or "unknown"
            token_json = _enrich_token_json(
                token_json,
                session=s,
                mailbox=mailbox,
                provider_key=provider_key,
                metadata=result.metadata,
            )
            _mark_cfmail_success()
            result.success = True
            result.token_json = token_json
            result.error_code = ""
            result.error_message = ""
            _set_stage("completed", token_source=token_source or "unknown")
            return result

        if post_create_gate == "add_phone":
            deferred_credentials = {
                "email": email,
                "password": password,
                "registration_proxy_url": proxy or "",
                "registration_fingerprint_profile": current_impersonate,
                "mailbox": {
                    **_mailbox_public_metadata(mailbox),
                    "token": str(mailbox.token or "").strip(),
                    "sid_token": str(mailbox.sid_token or "").strip(),
                },
            }
            return _fail(
                "add_phone_gate",
                "post_create_add_phone_gate",
                "注册流程已走到 add-phone gate，当前自动 codex token 提取失败",
                deferred_credentials=deferred_credentials,
                post_create_continue_url=post_create_continue_url,
                post_create_gate=post_create_gate,
            )

        logger.error(f"[线程 {thread_id}] [错误] 已完成注册，但仍未能获取 codex token")
        return _fail(
            "token_finalize",
            "token_extraction_failed",
            "已完成注册，但仍未能获取可用 codex token",
        )

    except Exception as e:
        logger.exception(f"[线程 {thread_id}] [错误] 运行过程中发生异常: {e}")
        logger.info(f"[线程 {thread_id}] [提示] 本轮失败，下一轮将继续重试")
        return _fail("exception", "unhandled_exception", str(e))
    finally:
        if reserved_mailbox_email:
            mailbox_dedupe_store.release(reserved_mailbox_email)


def run(
    proxy: Optional[str], provider_key: str, thread_id: int, mailtm_base: str
) -> RegistrationAttemptResult:
    """注册入口调度器。

    当前策略：
    - browser: 优先 browser signup，失败后回退 HTTP
    - hybrid: 优先 HTTP；若 token 提取失败则尝试 browser OAuth fallback；
      若 HTTP 注册整体失败，再尝试 browser signup
    """
    global _BROWSER_ENGINE_PHASE1_WARNED

    browser_runtime = get_browser_runtime_config().normalized()
    requested_engine = str(
        getattr(browser_runtime, "registration_engine", "http") or "http"
    ).strip().lower() or "http"
    browser_available = is_roxy_configured(browser_runtime)
    effective_engine = "http"

    if requested_engine in {"browser", "hybrid"} and not _BROWSER_ENGINE_PHASE1_WARNED:
        logger.warning(
            "[信息] browser/hybrid 模式已接入 browser signup + browser OAuth fallback；"
            "当前建议先小流量验证，再逐步放量"
        )
        _BROWSER_ENGINE_PHASE1_WARNED = True

    if requested_engine == "browser":
        if browser_available:
            browser_result = _run_browser(proxy, provider_key, thread_id, mailtm_base)
            browser_result.metadata.setdefault("requested_registration_engine", requested_engine)
            browser_result.metadata.setdefault("effective_registration_engine", "browser")
            browser_result.metadata["browser_signup_attempted"] = True
            if browser_result.success:
                return browser_result
            logger.warning(
                f"[线程 {thread_id}] [警告] browser signup 失败，准备回退到 HTTP："
                f"stage={browser_result.stage or 'unknown'} "
                f"code={browser_result.error_code or 'unknown'}"
            )
        else:
            logger.warning(f"[线程 {thread_id}] [警告] browser 模式已请求，但 Roxy 配置不完整，准备回退到 HTTP")
        effective_engine = "http_fallback_from_browser"

    result = _run_http(proxy, provider_key, thread_id, mailtm_base)
    result.metadata.setdefault("requested_registration_engine", requested_engine)
    result.metadata.setdefault("effective_registration_engine", effective_engine)
    if _should_try_browser_oauth_fallback(result, requested_engine):
        result.metadata["browser_oauth_attempted"] = True
        logger.info(f"[线程 {thread_id}] [信息] HTTP 注册已完成但 token 提取失败，开始尝试 browser OAuth fallback")
        browser_oauth_result = try_browser_oauth_password_login(
            email=result.email,
            password=result.password,
            mailbox_context=result.private_context.get("mailbox"),
            proxy_url=str(proxy or "").strip(),
            thread_id=thread_id,
        )
        browser_oauth_token_json = _accept_codex_token(
            browser_oauth_result.token_json if browser_oauth_result else None,
            thread_id=thread_id,
            source="browser_oauth_fallback",
            metadata=result.metadata,
        )
        if browser_oauth_result and browser_oauth_token_json:
            mailbox = _mailbox_from_private_context(
                result.private_context.get("mailbox"),
                fallback_email=result.email,
                fallback_provider=provider_key,
            )
            result.metadata.update(browser_oauth_result.metadata)
            result.metadata["token_source"] = "browser_oauth_fallback"
            result.metadata["requested_registration_engine"] = requested_engine
            result.metadata["effective_registration_engine"] = "browser_oauth_fallback"
            result.success = True
            result.stage = "completed"
            result.error_code = ""
            result.error_message = ""
            result.token_json = _enrich_token_json(
                browser_oauth_token_json,
                session=None,
                mailbox=mailbox,
                provider_key=provider_key,
                metadata=result.metadata,
            )
            return result
        result.metadata.setdefault("browser_oauth_attempted", True)
        result.metadata.setdefault("browser_oauth_success", False)

    if requested_engine == "hybrid" and not result.success and browser_available:
        logger.info(
            f"[线程 {thread_id}] [信息] HTTP 注册失败，开始尝试 browser signup fallback："
            f"stage={result.stage or 'unknown'} code={result.error_code or 'unknown'}"
        )
        browser_result = _run_browser(proxy, provider_key, thread_id, mailtm_base)
        browser_result.metadata.setdefault("requested_registration_engine", requested_engine)
        browser_result.metadata["browser_signup_attempted"] = True
        browser_result.metadata["hybrid_http_error_code"] = result.error_code or ""
        browser_result.metadata["hybrid_http_error_message"] = result.error_message or ""
        browser_result.metadata["hybrid_http_stage"] = result.stage or ""
        if browser_result.success:
            browser_result.metadata["effective_registration_engine"] = "browser_signup_fallback"
            return browser_result
        return browser_result

    return result


# ---------------------------------------------------------------------------
# 单 provider 注册封装（保留兼容函数名）
# ---------------------------------------------------------------------------


def _provider_fallback_chain(provider_key: str) -> List[str]:
    """构建邮箱服务提供商链。当前仅返回主 provider。"""
    primary = str(provider_key or "").strip().lower()
    chain: List[str] = []
    if primary:
        chain.append(primary)
    return chain


def run_with_fallback(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
    *,
    dingtalk_webhook: str = "",
    dingtalk_fallback_interval_seconds: int = DEFAULT_DINGTALK_FALLBACK_INTERVAL_SECONDS,
) -> Tuple[Optional[Tuple[str, str]], str]:
    """兼容旧接口名；当前不再执行任何保底邮箱回退。"""
    _ = dingtalk_webhook, dingtalk_fallback_interval_seconds
    provider_chain = _provider_fallback_chain(provider_key)
    last_used_provider = str(provider_key or "").strip().lower()

    for index, candidate_provider in enumerate(provider_chain):
        last_used_provider = candidate_provider

        attempt = run(proxy, candidate_provider, thread_id, mailtm_base)
        if attempt.success:
            return attempt.as_legacy_result(), candidate_provider

        logger.warning(
            f"[线程 {thread_id}] [警告] 使用邮箱服务 {candidate_provider} 的注册尝试失败："
            f"stage={attempt.stage or 'unknown'}"
            f", error_code={attempt.error_code or 'unknown'}"
            f", message={attempt.error_message or 'unknown'}"
        )

    return None, last_used_provider

__all__ = [
    "_provider_fallback_chain",
    "run",
    "run_with_fallback",
]
