"""Browser debug artifacts helpers."""

from __future__ import annotations

import os
from typing import Any

from .models import BrowserArtifacts


def ensure_browser_artifacts(root_dir: str) -> BrowserArtifacts:
    normalized_root = os.path.abspath(str(root_dir or "").strip() or "debug/browser")
    screenshots_dir = os.path.join(normalized_root, "screenshots")
    logs_dir = os.path.join(normalized_root, "logs")
    os.makedirs(screenshots_dir, exist_ok=True)
    os.makedirs(logs_dir, exist_ok=True)
    return BrowserArtifacts(
        root_dir=normalized_root,
        screenshots_dir=screenshots_dir,
        logs_dir=logs_dir,
    )


def build_screenshot_path(artifacts: BrowserArtifacts, label: str) -> str:
    safe_label = str(label or "page").strip() or "page"
    safe_label = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in safe_label)
    return os.path.join(artifacts.screenshots_dir, f"{safe_label}.png")


async def save_page_screenshot(page: Any, artifacts: BrowserArtifacts, label: str) -> str:
    path = build_screenshot_path(artifacts, label)
    await page.screenshot(path=path)
    return path
