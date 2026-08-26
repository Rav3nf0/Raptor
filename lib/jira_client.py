"""Shared Jira HTTP client builder used across the app."""
from __future__ import annotations

import httpx


def build_jira_client(
    jira_url: str,
    jira_email: str | None,
    jira_token: str | None,
    verify_ssl: bool = True,
) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=jira_url.rstrip("/"),
        auth=httpx.BasicAuth(jira_email or "", jira_token or ""),
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        timeout=20.0,
        verify=verify_ssl,
    )
