"""Browser CDP session helpers."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, Tuple

from .models import BrowserHandle


@asynccontextmanager
async def open_cdp_page(
    handle: BrowserHandle,
) -> AsyncIterator[Tuple[object, object, object]]:
    try:
        from patchright.async_api import async_playwright
    except Exception as exc:  # pragma: no cover - depends on optional runtime
        raise RuntimeError(
            "browser runtime requires patchright.async_api; install patchright first"
        ) from exc

    async with async_playwright() as playwright:
        browser = await playwright.chromium.connect_over_cdp(handle.ws_endpoint)
        contexts = getattr(browser, "contexts", [])
        if not contexts:
            raise RuntimeError("cdp connection established but no browser context is available")
        context = contexts[0]
        pages = getattr(context, "pages", [])
        page = pages[0] if pages else await context.new_page()
        yield browser, context, page
