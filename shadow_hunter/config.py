"""SentinelShadow configuration — integrates with DeepIntel's env/Secrets Manager setup."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic_settings import BaseSettings, SettingsConfigDict

_MODULE_DIR = Path(__file__).resolve().parent
_ENV_FILE = _MODULE_DIR.parent / ".env"  # absolute path — works regardless of CWD


class ShadowConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SHADOW_", env_file=str(_ENV_FILE), extra="ignore")

    mode: str = "mock"  # "mock" reads CSVs; "live" hits Defender API
    data_dir: Path = _MODULE_DIR / "data"
    allowlist_path: Path = _MODULE_DIR / "allowlist" / "rules.yaml"

    # Azure AD creds — required in live mode, ignored in mock
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    sentinel_subscription_id: str = ""
    sentinel_resource_group: str = ""
    sentinel_workspace_name: str = ""

    # Set to False when a corporate SSL-inspection proxy injects a self-signed cert
    ssl_verify: bool = True


_config: Optional[ShadowConfig] = None


def get_shadow_config() -> ShadowConfig:
    global _config
    if _config is None:
        _config = ShadowConfig()
    return _config


def reset_shadow_config() -> None:
    global _config
    _config = None
