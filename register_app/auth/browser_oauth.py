"""Browser OAuth fallback flow."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
import logging
import os
import re
import time
from typing import Any, Dict, Optional, Set

from ..browser import (
    BrowserProfileConfig,
    BrowserRuntimeConfig,
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
from ..mail.providers import TempMailbox
from ..registration.mailbox import get_mailbox_message_snapshot, get_oai_code
from .oauth import generate_oauth_url, submit_callback_url

logger = logging.getLogger("openai_register")

_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@dataclass(frozen=True)
class BrowserOAuthResult:
    token_json: str
    metadata: Dict[str, Any] = field(default_factory=dict)


def _runtime_for_browser_oauth() -> BrowserRuntimeConfig:
    return get_browser_runtime_config().normalized()


async def _is_visible(locator: Any) -> bool:
    try:
        if await locator.count() <= 0:
            return False
        return bool(await locator.first.is_visible())
    except Exception:
        return False


def _has_callback_code(value: str) -> bool:
    return "localhost:1455/auth/callback" in str(value or "") and "code=" in str(value or "")


async def _maybe_screenshot(page: Any, *, enabled: bool, artifacts: Any, label: str) -> str:
    if not enabled or artifacts is None:
        return ""
    try:
        return await save_page_screenshot(page, artifacts, label)
    except Exception:
        return ""


def _build_browser_mailbox(context: Dict[str, Any]) -> Optional[TempMailbox]:
    if not isinstance(context, dict):
        return None
    email = str(context.get("email") or "").strip()
    provider = str(context.get("provider") or "").strip()
    if not email or not provider:
        return None
    return TempMailbox(
        email=email,
        provider=provider,
        token=str(context.get("token") or "").strip(),
        api_base=str(context.get("api_base") or "").strip(),
        login=str(context.get("login") or "").strip(),
        domain=str(context.get("domain") or "").strip(),
        sid_token=str(context.get("sid_token") or "").strip(),
        password=str(context.get("password") or "").strip(),
        config_name=str(context.get("config_name") or "").strip(),
    )


def try_browser_oauth_password_login(
    *,
    email: str,
    password: str,
    mailbox_context: Optional[Dict[str, Any]],
    proxy_url: str,
    thread_id: int,
    reuse_profile_id: str = "",
    close_profile: bool = True,
) -> Optional[BrowserOAuthResult]:
    runtime = _runtime_for_browser_oauth()
    if not is_roxy_configured(runtime):
        logger.warning(
            f"[线程 {thread_id}] [警告] browser OAuth fallback 已请求，但 Roxy 配置不完整，已跳过"
        )
        return None

    account = str(email or "").strip()
    pwd = str(password or "").strip()
    if not account or not pwd:
        return None

    mailbox = _build_browser_mailbox(mailbox_context or {})
    client = RoxyClient(port=runtime.roxy_port, token=runtime.roxy_token)
    profile_id = str(reuse_profile_id or "").strip()
    owns_profile = not bool(profile_id)
    artifacts = ensure_browser_artifacts(os.path.join(_PROJECT_ROOT, "debug", "browser_oauth"))

    async def _run_browser_flow() -> Optional[str]:
        nonlocal profile_id
        oauth = generate_oauth_url()
        callback_url_holder = [""]
        used_codes: Set[str] = set()
        mailbox_snapshot: Set[str] = (
            get_mailbox_message_snapshot(mailbox, thread_id, {"http": proxy_url, "https": proxy_url} if proxy_url else None)
            if mailbox
            else set()
        )

        profile_config = BrowserProfileConfig(
            window_name=f"openai_oauth_{thread_id}_{int(time.time())}",
            workspace_id=runtime.roxy_workspace_id,
            proxy_url=proxy_url,
            core_version=runtime.core_version,
            os_name=runtime.os_name,
        )
        if not profile_id:
            profile_id = create_roxy_profile(client, profile_config)
        handle = open_roxy_profile(
            client,
            profile_id=profile_id,
            launch_args=list(profile_config.launch_args),
            proxy_url=proxy_url,
            fingerprint_profile=f"roxy:{profile_id}",
            metadata={
                "core_version": runtime.core_version,
                "os_name": runtime.os_name,
            },
        )

        async with open_cdp_page(handle) as (_browser, context, page):
            async def _intercept_callback(route: Any) -> None:
                callback_url_holder[0] = str(route.request.url or "").strip()
                await route.fulfill(
                    status=200,
                    content_type="text/html",
                    body="<html><body><h1>Auth Complete</h1></body></html>",
                )

            def _on_request(request: Any) -> None:
                url = str(getattr(request, "url", "") or "").strip()
                if _has_callback_code(url) and not callback_url_holder[0]:
                    callback_url_holder[0] = url

            await context.route("http://localhost:1455/auth/callback*", _intercept_callback)
            page.on("request", _on_request)
            await page.goto(oauth.auth_url, timeout=60000, wait_until="domcontentloaded")
            await asyncio.sleep(2)
            await _maybe_screenshot(
                page,
                enabled=runtime.screenshots_enabled,
                artifacts=artifacts,
                label=f"thread_{thread_id}_step_00_authorize",
            )

            for step in range(30):
                if callback_url_holder[0]:
                    break

                current_url = str(page.url or "")
                lowered_url = current_url.lower()

                if _has_callback_code(current_url):
                    callback_url_holder[0] = current_url
                    break

                try:
                    email_visible = await _is_visible(page.locator('input[name="email"], input[type="email"]'))
                    pwd_visible = await _is_visible(page.locator('input[name="current-password"], input[type="password"]'))
                    otp_visible = await _is_visible(page.locator('input[name="code"], input[inputmode="numeric"]'))
                except Exception:
                    email_visible = pwd_visible = otp_visible = False

                page_class = "unknown"
                if "chrome-error://" in lowered_url:
                    page_class = "chrome_error"
                elif "localhost:1455/auth/callback" in lowered_url:
                    page_class = "callback"
                elif otp_visible or "email-verification" in lowered_url:
                    page_class = "otp"
                elif pwd_visible or "/password" in lowered_url:
                    page_class = "login_password"
                elif email_visible or "/log-in" in lowered_url or "/sign-in" in lowered_url:
                    page_class = "login_email"
                elif any(keyword in lowered_url for keyword in ("consent", "workspace", "organization", "sign-in-with")):
                    page_class = "consent_or_select"

                await _maybe_screenshot(
                    page,
                    enabled=runtime.screenshots_enabled,
                    artifacts=artifacts,
                    label=f"thread_{thread_id}_step_{step+1:02d}_{page_class}",
                )

                if page_class == "login_email":
                    locator = page.locator('input[name="email"], input[type="email"]')
                    await locator.first.fill(account)
                    await asyncio.sleep(0.3)
                    submit = page.locator(
                        'button[type="submit"][name="intent"][value="email"], button[type="submit"]'
                    )
                    await submit.first.click()
                elif page_class == "login_password":
                    if mailbox:
                        mailbox_snapshot = get_mailbox_message_snapshot(
                            mailbox,
                            thread_id,
                            {"http": proxy_url, "https": proxy_url} if proxy_url else None,
                        )
                    locator = page.locator('input[name="current-password"], input[type="password"]')
                    await locator.first.fill(pwd)
                    await asyncio.sleep(0.3)
                    submit = page.locator(
                        'button[type="submit"][name="intent"][value="validate"], button[type="submit"]'
                    )
                    await submit.first.click()
                elif page_class == "otp":
                    if not mailbox:
                        logger.warning(
                            f"[线程 {thread_id}] [警告] browser OAuth 进入 OTP 页面，但没有邮箱上下文"
                        )
                        return None

                    code = get_oai_code(
                        mailbox,
                        thread_id,
                        {"http": proxy_url, "https": proxy_url} if proxy_url else None,
                        skip_message_ids=mailbox_snapshot,
                        skip_codes=used_codes,
                    )
                    if not code:
                        logger.warning(f"[线程 {thread_id}] [警告] browser OAuth 未能获取登录验证码")
                        return None
                    used_codes.add(code)
                    locator = page.locator('input[name="code"], input[inputmode="numeric"]')
                    await locator.first.fill(code)
                    await asyncio.sleep(0.3)
                    submit = page.locator('button[type="submit"], button[name="intent"][value="submit"]')
                    await submit.first.click()
                elif page_class == "consent_or_select":
                    clicked = False
                    selectors = [
                        'button:has-text("Continue")',
                        'button:has-text("Allow")',
                        'button:has-text("Accept")',
                        'button:has-text("Agree")',
                        'button:has-text("Next")',
                        'button[type="submit"]',
                    ]
                    for selector in selectors:
                        locator = page.locator(selector)
                        if await _is_visible(locator):
                            await locator.first.click()
                            clicked = True
                            break
                    if not clicked:
                        try:
                            await page.keyboard.press("Enter")
                        except Exception:
                            pass
                elif page_class == "chrome_error":
                    body_text = ""
                    try:
                        body_text = (await page.locator("body").inner_text())[:500]
                    except Exception:
                        body_text = ""
                    matched = re.search(r"http://localhost:1455/auth/callback[^\s]+", body_text)
                    if matched:
                        callback_url_holder[0] = matched.group(0)
                        break
                    try:
                        await page.go_back(timeout=10000, wait_until="domcontentloaded")
                    except Exception:
                        await page.goto(oauth.auth_url, timeout=30000, wait_until="domcontentloaded")
                elif page_class == "callback":
                    callback_url_holder[0] = current_url
                    break
                else:
                    generic_submit = page.locator('button[type="submit"], button:has-text("Continue"), button:has-text("Next")')
                    if await _is_visible(generic_submit):
                        await generic_submit.first.click()
                    else:
                        await asyncio.sleep(2)

                for _ in range(10):
                    await asyncio.sleep(1)
                    if callback_url_holder[0]:
                        break
                    if str(page.url or "") != current_url:
                        break

            callback_url = str(callback_url_holder[0] or "").strip()
            if not callback_url:
                return None
            return submit_callback_url(
                callback_url=callback_url,
                expected_state=oauth.state,
                code_verifier=oauth.code_verifier,
                redirect_uri=oauth.redirect_uri,
            )

    try:
        token_json = asyncio.run(_run_browser_flow())
    except Exception as exc:
        logger.warning(f"[线程 {thread_id}] [警告] browser OAuth fallback 异常: {exc}")
        token_json = None
    finally:
        if profile_id and close_profile and owns_profile:
            try:
                close_roxy_profile(client, profile_id)
            except Exception:
                pass

    if not token_json:
        return None

    return BrowserOAuthResult(
        token_json=token_json,
        metadata={
            "browser_oauth_success": True,
            "browser_oauth_used": True,
            "browser_oauth_reused_profile": not owns_profile,
            "browser_oauth_backend": runtime.backend,
            "browser_oauth_profile_id": profile_id,
            "browser_oauth_fingerprint_profile": f"roxy:{profile_id}" if profile_id else "",
        },
    )


__all__ = ["BrowserOAuthResult", "try_browser_oauth_password_login"]
