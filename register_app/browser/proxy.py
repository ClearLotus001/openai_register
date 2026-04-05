"""Proxy helpers for browser backends."""

from __future__ import annotations

from urllib.parse import urlparse


def parse_proxy_url(proxy_url: str) -> dict[str, str]:
    normalized = str(proxy_url or "").strip()
    if not normalized:
        return {"proxyMethod": "noproxy"}

    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    if not host:
        raise ValueError("proxy url missing host")

    scheme = str(parsed.scheme or "http").strip().lower()
    if scheme in {"socks", "socks5h"}:
        scheme = "socks5"
    if scheme not in {"http", "https", "socks5"}:
        scheme = "http"

    protocol = scheme.upper()
    default_port = 1080 if scheme == "socks5" else 80
    return {
        "proxyMethod": "custom",
        "proxyCategory": protocol,
        "ipType": "IPV4",
        "protocol": protocol,
        "host": host,
        "port": str(parsed.port or default_port),
        "proxyUserName": parsed.username or "",
        "proxyPassword": parsed.password or "",
    }
