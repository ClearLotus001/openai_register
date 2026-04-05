# -*- coding: utf-8 -*-
"""核心注册流程与邮箱路由逻辑。"""

from .common import (
    RegistrationAttemptResult,
    _build_random_signup_profile,
    _build_request_proxies,
    _enrich_token_json,
    _extract_session_token_from_session,
    _extract_response_error_code_message,
    _generate_password,
    _is_invalid_auth_step,
    _mailbox_public_metadata,
    _mailbox_wait_failure_reason,
    _post_create_account_with_retry,
    _preview_response_text,
    _random_birthdate,
    _random_name_part,
    _random_profile_name,
    _response_json_object,
    get_auto_proxy,
)
from .flow import _provider_fallback_chain, run, run_with_fallback
from .browser_flow import run_browser
from .mailbox import (
    MAILTM_BASE,
    TempMailbox,
    get_mailbox_message_snapshot,
    get_oai_code,
    get_temp_mailbox,
)

__all__ = [
    "MAILTM_BASE",
    "RegistrationAttemptResult",
    "TempMailbox",
    "_build_random_signup_profile",
    "_build_request_proxies",
    "_enrich_token_json",
    "_extract_session_token_from_session",
    "_extract_response_error_code_message",
    "_generate_password",
    "_is_invalid_auth_step",
    "_mailbox_public_metadata",
    "_mailbox_wait_failure_reason",
    "_provider_fallback_chain",
    "_post_create_account_with_retry",
    "_preview_response_text",
    "_random_birthdate",
    "_random_name_part",
    "_random_profile_name",
    "_response_json_object",
    "get_auto_proxy",
    "get_mailbox_message_snapshot",
    "get_oai_code",
    "get_temp_mailbox",
    "run",
    "run_browser",
    "run_with_fallback",
]
