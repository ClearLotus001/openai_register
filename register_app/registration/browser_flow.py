"""Browser-based registration flow."""

from __future__ import annotations

import asyncio
import builtins
import logging
import os
from typing import Any, Dict, Optional, Set

from curl_cffi import requests

from ..auth.browser_oauth import try_browser_oauth_password_login
from ..browser import (
    BrowserProfileConfig,
    RoxyClient,
    close_roxy_profile,
    create_roxy_profile,
    ensure_browser_artifacts,
    get_browser_runtime_config,
    is_roxy_configured,
    open_cdp_page,
    open_roxy_profile,
    save_page_screenshot,
)
from ..mail.cfmail import reload_cfmail_accounts_if_needed
from ..mail.dedupe import get_mailbox_dedupe_store
from ..mail.providers import TempMailbox
from .common import (
    RegistrationAttemptResult,
    _accept_codex_token,
    _build_random_signup_profile,
    _build_request_proxies,
    _enrich_token_json,
    _generate_password,
    _mailbox_public_metadata,
    _mailbox_wait_failure_reason,
)
from .mailbox import get_mailbox_message_snapshot, get_oai_code, get_temp_mailbox

logger = logging.getLogger("openai_register")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


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


async def _is_visible(locator: Any) -> bool:
    try:
        if await locator.count() <= 0:
            return False
        return bool(await locator.first.is_visible())
    except Exception:
        return False


async def _maybe_screenshot(page: Any, *, enabled: bool, artifacts: Any, label: str) -> str:
    if not enabled or artifacts is None:
        return ""
    try:
        return await save_page_screenshot(page, artifacts, label)
    except Exception:
        return ""


async def _click_first_visible(page: Any, selectors: list[str]) -> bool:
    for selector in selectors:
        locator = page.locator(selector)
        if await _is_visible(locator):
            await locator.first.click()
            return True
    return False


def run_browser(
    proxy: Optional[str],
    provider_key: str,
    thread_id: int,
    mailtm_base: str,
) -> RegistrationAttemptResult:
    runtime = get_browser_runtime_config().normalized()
    result = RegistrationAttemptResult(
        provider_key=str(provider_key or "").strip().lower(),
        metadata={
            "thread_id": thread_id,
            "requested_registration_engine": "browser",
            "effective_registration_engine": "browser",
        },
    )

    def _set_stage(stage: str, **metadata: Any) -> None:
        result.stage = stage
        if metadata:
            result.metadata.update(metadata)

    def _fail(stage: str, error_code: str, error_message: str, **metadata: Any) -> RegistrationAttemptResult:
        _set_stage(stage, **metadata)
        result.success = False
        result.error_code = str(error_code or "").strip()
        result.error_message = str(error_message or "").strip()
        return result

    if not is_roxy_configured(runtime):
        return _fail(
            "browser_runtime_check",
            "browser_runtime_unavailable",
            "RoxyBrowser 配置不完整，无法执行 browser registration",
        )

    if provider_key == "cfmail":
        reload_cfmail_accounts_if_needed()

    proxies: Any = _build_request_proxies(proxy)
    mailbox_dedupe_store = get_mailbox_dedupe_store()
    reserved_mailbox_email = ""
    mailbox: Optional[TempMailbox] = None
    profile_id = ""
    client = RoxyClient(port=runtime.roxy_port, token=runtime.roxy_token)
    artifacts = ensure_browser_artifacts(os.path.join(_PROJECT_ROOT, "debug", "browser_registration"))

    try:
        _set_stage("network_check")
        network_session = requests.Session(proxies=proxies, impersonate="chrome131")
        trace = network_session.get("https://cloudflare.com/cdn-cgi/trace", timeout=10).text
        loc = None
        for line in trace.splitlines():
            if line.startswith("loc="):
                loc = line.split("=", 1)[1].strip()
                break
        result.metadata["exit_loc"] = loc
        result.metadata["registration_proxy_url"] = str(proxy or "").strip()
        if loc != "US":
            if not builtins.yasal_bypass_ip_choice:
                return _fail("network_check", "non_us_exit_blocked", f"当前出口地区 {loc} 不符合要求", exit_loc=loc)
            logger.info(f"[线程 {thread_id}] [信息] browser registration 当前节点地区 ({loc}) 不是 US，已默认继续执行")
        if loc in ("CN", "HK") and not builtins.yasal_bypass_ip_choice:
            return _fail("network_check", "high_risk_exit", f"当前出口地区 {loc} 风险过高", exit_loc=loc)

        _set_stage("mailbox_create")
        duplicate_count = 0
        for _ in range(5):
            candidate = get_temp_mailbox(provider_key, thread_id, proxies, mailtm_base=mailtm_base)
            if not candidate:
                mailbox = None
                break
            if mailbox_dedupe_store.reserve(candidate.email):
                mailbox = candidate
                reserved_mailbox_email = candidate.email
                break
            duplicate_count += 1
            logger.warning(f"[线程 {thread_id}] [警告] 当前邮箱 {candidate.email} 已在本地去重名单中，准备重新申请新邮箱")
        if not mailbox:
            return _fail(
                "mailbox_create",
                "mailbox_duplicate_exhausted" if duplicate_count > 0 else "mailbox_unavailable",
                "临时邮箱服务不可用或短时间内重复命中过往邮箱",
                mailbox_duplicate_retries=duplicate_count,
            )

        result.email = mailbox.email
        result.metadata.update(
            {
                "mailbox_provider": mailbox.provider,
                "mailbox_email": mailbox.email,
                "mailbox_metadata": _mailbox_public_metadata(mailbox),
                "mailbox_duplicate_retries": duplicate_count,
            }
        )
        result.private_context["mailbox"] = _mailbox_private_context(mailbox)

        password = _generate_password()
        signup_profile = _build_random_signup_profile()
        result.password = password
        result.metadata["signup_profile"] = dict(signup_profile)

        async def _run_signup() -> tuple[bool, Dict[str, Any]]:
            nonlocal profile_id
            signup_snapshot: Set[str] = get_mailbox_message_snapshot(mailbox, thread_id, proxies)
            used_codes: Set[str] = set()
            profile_config = BrowserProfileConfig(
                window_name=f"openai_signup_{thread_id}",
                workspace_id=runtime.roxy_workspace_id,
                proxy_url=str(proxy or "").strip(),
                core_version=runtime.core_version,
                os_name=runtime.os_name,
            )
            profile_id = create_roxy_profile(client, profile_config)
            handle = open_roxy_profile(
                client,
                profile_id=profile_id,
                launch_args=list(profile_config.launch_args),
                proxy_url=str(proxy or "").strip(),
                fingerprint_profile=f"roxy:{profile_id}",
                metadata={
                    "core_version": runtime.core_version,
                    "os_name": runtime.os_name,
                },
            )
            result.metadata["fingerprint_profile"] = f"roxy:{profile_id}"
            result.metadata["browser_profile_id"] = profile_id
            result.metadata["browser_backend"] = runtime.backend

            async with open_cdp_page(handle) as (_browser, _context, page):
                signup_url = "https://chatgpt.com/auth/login?callbackUrl=%2F&screen_hint=signup"
                await page.goto(signup_url, timeout=60000, wait_until="domcontentloaded")
                await asyncio.sleep(2)
                await _maybe_screenshot(
                    page,
                    enabled=runtime.screenshots_enabled,
                    artifacts=artifacts,
                    label=f"thread_{thread_id}_step_00_start",
                )

                for nav_attempt in range(4):
                    email_locator = page.locator('input[name="email"], input#email, input[type="email"]')
                    if await _is_visible(email_locator):
                        break
                    await _click_first_visible(
                        page,
                        [
                            'button:has-text("Accept all")',
                            'button:has-text("Allow all")',
                            '[data-testid="signup-button"]',
                            'button:has-text("Sign up")',
                            'button:has-text("Create account")',
                        ],
                    )
                    await asyncio.sleep(2 + nav_attempt)
                email_locator = page.locator('input[name="email"], input#email, input[type="email"]')
                if not await _is_visible(email_locator):
                    return False, {
                        "stage": "signup_start",
                        "error_code": "browser_signup_email_input_missing",
                        "error_message": "未找到注册邮箱输入框",
                    }

                await email_locator.first.fill(mailbox.email)
                await asyncio.sleep(0.3)
                if not await _click_first_visible(
                    page,
                    ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Next")'],
                ):
                    return False, {
                        "stage": "signup_start",
                        "error_code": "browser_signup_submit_missing",
                        "error_message": "未找到注册提交按钮",
                    }

                for step in range(22):
                    current_url = str(page.url or "")
                    lowered_url = current_url.lower()
                    await _maybe_screenshot(
                        page,
                        enabled=runtime.screenshots_enabled,
                        artifacts=artifacts,
                        label=f"thread_{thread_id}_step_{step+1:02d}",
                    )

                    if "chatgpt.com" in lowered_url and "auth" not in lowered_url:
                        return True, {"final_url": current_url}

                    retry_locator = page.locator('button:has-text("Try again"), button:has-text("Retry")')
                    if await _is_visible(retry_locator):
                        await retry_locator.first.click()
                        await asyncio.sleep(3)
                        continue

                    if "create-account/password" in lowered_url or await _is_visible(page.locator('input[type="password"]')):
                        locator = page.locator('input[type="password"], input[name="password"]')
                        await locator.first.fill(password)
                        await asyncio.sleep(0.3)
                        await _click_first_visible(
                            page,
                            ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Next")'],
                        )
                    elif "email-verification" in lowered_url or await _is_visible(page.locator('input[name="code"], input[inputmode="numeric"]')):
                        code = get_oai_code(
                            mailbox,
                            thread_id,
                            proxies,
                            skip_message_ids=signup_snapshot,
                            skip_codes=used_codes,
                        )
                        wait_reason, wait_diagnostics = _mailbox_wait_failure_reason(mailbox)
                        if wait_diagnostics:
                            result.metadata["otp_wait_diagnostics"] = wait_diagnostics
                        if not code:
                            return False, {
                                "stage": "email_otp_wait",
                                "error_code": wait_reason,
                                "error_message": "browser registration 未获取到验证码",
                            }
                        used_codes.add(code)
                        locator = page.locator('input[name="code"], input[inputmode="numeric"]')
                        await locator.first.fill(code)
                        await asyncio.sleep(0.3)
                        await _click_first_visible(
                            page,
                            ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Next")'],
                        )
                    elif "about-you" in lowered_url or await _is_visible(page.locator('input[name="name"][type="text"]')):
                        name_locator = page.locator('input[name="name"][type="text"], input[name="name"]')
                        if await _is_visible(name_locator):
                            await name_locator.first.fill(str(signup_profile.get("name") or ""))
                            await asyncio.sleep(0.3)
                        age_locator = page.locator('input[name="age"]')
                        birthdate = str(signup_profile.get("birthdate") or "")
                        if await _is_visible(age_locator) and birthdate:
                            birth_year = int(birthdate.split("-")[0])
                            age = max(18, 2026 - birth_year)
                            await age_locator.first.fill(str(age))
                        else:
                            selects = page.locator("select")
                            if birthdate and await selects.count() >= 3:
                                month, day, year = birthdate.split("-")[1], birthdate.split("-")[2], birthdate.split("-")[0]
                                try:
                                    await selects.nth(0).select_option(value=str(int(month)))
                                    await selects.nth(1).select_option(value=str(int(day)))
                                    await selects.nth(2).select_option(value=year)
                                except Exception:
                                    pass
                        await asyncio.sleep(0.3)
                        await _click_first_visible(
                            page,
                            ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Next")'],
                        )
                    elif "log-in-or-create-account" in lowered_url or "screen_hint=signup" in lowered_url:
                        email_locator = page.locator('input[name="email"], input#email, input[type="email"]')
                        if await _is_visible(email_locator):
                            await email_locator.first.fill(mailbox.email)
                            await asyncio.sleep(0.3)
                            await _click_first_visible(
                                page,
                                ['button[type="submit"]', 'button:has-text("Continue")', 'button:has-text("Next")'],
                            )
                    elif "add-phone" in lowered_url:
                        return False, {
                            "stage": "add_phone_gate",
                            "error_code": "post_create_add_phone_gate",
                            "error_message": "browser registration 命中 add-phone gate",
                        }
                    else:
                        body_text = ""
                        try:
                            body_text = (await page.locator("body").inner_text())[:500]
                        except Exception:
                            body_text = ""
                        if "phone" in body_text.lower() and "verify" in body_text.lower():
                            return False, {
                                "stage": "add_phone_gate",
                                "error_code": "post_create_add_phone_gate",
                                "error_message": "browser registration 页面疑似要求手机验证",
                            }
                        clicked = await _click_first_visible(
                            page,
                            [
                                'button[type="submit"]',
                                'button:has-text("Continue")',
                                'button:has-text("Next")',
                                'button:has-text("Agree")',
                                'button:has-text("Accept")',
                                'button:has-text("Skip")',
                            ],
                        )
                        if not clicked:
                            return False, {
                                "stage": "unknown_page",
                                "error_code": "browser_signup_unknown_page",
                                "error_message": body_text[:200] or "browser registration 卡在未知页面",
                            }

                    original_url = current_url
                    for _ in range(12):
                        await asyncio.sleep(1)
                        if str(page.url or "") != original_url:
                            break

                return False, {
                    "stage": "browser_signup_timeout",
                    "error_code": "browser_signup_timeout",
                    "error_message": "browser registration 状态机超时",
                }

        try:
            signup_success, signup_meta = asyncio.run(_run_signup())
        except Exception as exc:
            return _fail("browser_signup_exception", "browser_signup_exception", str(exc))

        if not signup_success:
            return _fail(
                str(signup_meta.get("stage") or "browser_signup_failed"),
                str(signup_meta.get("error_code") or "browser_signup_failed"),
                str(signup_meta.get("error_message") or "browser signup failed"),
                **{k: v for k, v in signup_meta.items() if k not in {"stage", "error_code", "error_message"}},
            )

        result.metadata.update(signup_meta)
        result.metadata["browser_signup_success"] = True

        browser_oauth_result = try_browser_oauth_password_login(
            email=mailbox.email,
            password=password,
            mailbox_context=result.private_context.get("mailbox"),
            proxy_url=str(proxy or "").strip(),
            thread_id=thread_id,
            reuse_profile_id=profile_id,
            close_profile=False,
        )
        browser_oauth_token_json = _accept_codex_token(
            browser_oauth_result.token_json if browser_oauth_result else None,
            thread_id=thread_id,
            source="browser_signup_oauth",
            metadata=result.metadata,
        )
        if not browser_oauth_result or not browser_oauth_token_json:
            return _fail(
                "token_finalize",
                "token_extraction_failed",
                "browser registration 已完成，但 browser OAuth fallback 未获取到 codex token",
            )

        result.metadata.update(browser_oauth_result.metadata)
        result.metadata["token_source"] = "browser_signup_oauth"
        result.metadata["effective_registration_engine"] = "browser"
        result.metadata["browser_profile_reused_for_oauth"] = True
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
    finally:
        if reserved_mailbox_email:
            mailbox_dedupe_store.release(reserved_mailbox_email)
        if profile_id:
            try:
                close_roxy_profile(client, profile_id)
            except Exception:
                pass
