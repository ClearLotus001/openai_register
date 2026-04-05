"""Roxy browser backend client."""

from __future__ import annotations

from typing import Any, Dict, Optional

from curl_cffi import requests


class RoxyClient:
    def __init__(
        self,
        *,
        port: int,
        token: str,
        host: str = "127.0.0.1",
        timeout: int = 20,
    ) -> None:
        self.port = int(port)
        self.host = str(host or "127.0.0.1").strip() or "127.0.0.1"
        self.token = str(token or "").strip()
        self.timeout = max(1, int(timeout))
        self.url = f"http://{self.host}:{self.port}"

    def _headers(self) -> Dict[str, str]:
        return {
            "Content-Type": "application/json",
            "token": self.token,
        }

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        response = requests.get(
            self.url + path,
            params=params,
            headers=self._headers(),
            timeout=self.timeout,
        )
        return response.json() if response.content else {}

    def _post(self, path: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        response = requests.post(
            self.url + path,
            json=payload,
            headers=self._headers(),
            timeout=self.timeout,
        )
        return response.json() if response.content else {}

    def health(self) -> Dict[str, Any]:
        return self._get("/health")

    def workspace_project(self) -> Dict[str, Any]:
        return self._get("/browser/workspace")

    def browser_create(self, data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return self._post("/browser/create", data)

    def browser_open(
        self,
        profile_id: str,
        *,
        args: Optional[list[str]] = None,
    ) -> Dict[str, Any]:
        return self._post(
            "/browser/open",
            {
                "dirId": str(profile_id or "").strip(),
                "args": list(args or []),
            },
        )

    def browser_close(self, profile_id: str) -> Dict[str, Any]:
        return self._post("/browser/close", {"dirId": str(profile_id or "").strip()})

    def browser_delete(self, workspace_id: int, profile_ids: list[str]) -> Dict[str, Any]:
        return self._post(
            "/browser/delete",
            {
                "workspaceId": int(workspace_id),
                "dirIds": list(profile_ids or []),
            },
        )

    def browser_connection_info(self, profile_ids: Optional[list[str]] = None) -> Dict[str, Any]:
        return self._get("/browser/connection_info", {"dirIds": list(profile_ids or [])})
