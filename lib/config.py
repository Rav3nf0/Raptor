"""
App config — env + AWS Secrets Manager in production.
Expects secret (JSON): mongodb_uri, s3_raw_intel_bucket, s3_audit_export_bucket, aws_region, etc.
"""
import os
from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings

from lib.secretsmanager import SecretsManager

# Maps Secrets Manager JSON keys → os.environ variable names.
# Written to os.environ so modules that read os.getenv() directly
# (mde_client, cyble_ingestion, etc.) pick up prod values regardless
# of import order.
_SECRET_ENV_MAP: dict[str, str] = {
    "mongodb_uri":            "MONGODB_URI",
    "mongodb_db":             "MONGODB_DB",
    "gemini_api_key":         "GEMINI_API_KEY",
    "cyble_api_token":        "CYBLE_API_TOKEN",
    "cyble_api_key":          "CYBLE_API_KEY",
    "mde_tenant_id":          "MDE_TENANT_ID",
    "mde_client_id":          "MDE_CLIENT_ID",
    "mde_client_secret":      "MDE_CLIENT_SECRET",
    "virustotal_api_key":     "VIRUSTOTAL_API_KEY",
    "urlscan_api_key":        "URLSCAN_API_KEY",
    "shodan_api_key":         "SHODAN_API_KEY",
    "jira_email":                       "JIRA_EMAIL",
    "jira_api_token":                   "JIRA_API_TOKEN",
    "socket_scan_api_url":              "SOCKET_SCAN_API_URL",
    "s3_raw_intel_bucket":              "S3_RAW_INTEL_BUCKET",
    "s3_audit_export_bucket":           "S3_AUDIT_EXPORT_BUCKET",
    "aws_region":                       "AWS_REGION",
    "otx_api_key":                      "OTX_API_KEY",
    "shadow_tenant_id":                 "SHADOW_TENANT_ID",
    "shadow_client_id":                 "SHADOW_CLIENT_ID",
    "shadow_client_secret":             "SHADOW_CLIENT_SECRET",
    "shadow_sentinel_subscription_id":  "SHADOW_SENTINEL_SUBSCRIPTION_ID",
    "shadow_sentinel_resource_group":   "SHADOW_SENTINEL_RESOURCE_GROUP",
    "shadow_sentinel_workspace_name":   "SHADOW_SENTINEL_WORKSPACE_NAME",
    # Log Analytics workspace for sentinel_run_kql (agent hunts). The Cyble
    # ingestion service already queries this workspace via SENTINEL_* in its own
    # .env; the main pod loads from Secrets Manager, so map the same names here so
    # the agent's run_sentinel_query is configured too. (run_sentinel_query also
    # falls back to SHADOW_SENTINEL_* if these keys aren't in the secret.)
    "sentinel_subscription_id":         "SENTINEL_SUBSCRIPTION_ID",
    "sentinel_resource_group":          "SENTINEL_RESOURCE_GROUP",
    "sentinel_workspace_name":          "SENTINEL_WORKSPACE_NAME",
    "deepintel_username":               "DEEPINTEL_USERNAME",
    "deepintel_password":               "DEEPINTEL_PASSWORD",
    "deepintel_jwt_secret":             "DEEPINTEL_JWT_SECRET",
    # Agent LLM backend (Bedrock / Mantle) — promoted so the backends' os.getenv reads work in prod
    "agent_backend":                    "AGENT_BACKEND",
    "agent_model":                      "AGENT_MODEL",
    "mantle_api_key":                   "MANTLE_API_KEY",
    "MANTLE_API":                       "MANTLE_API_KEY",   # actual secret JSON key name
    "anthropic_workspace_id":           "ANTHROPIC_WORKSPACE_ID",
    # SMTP for takedown emails — stored as SMTP_USER/SMTP_PASSWORD in AWS secret
    "SMTP_USER":                        "SMTP_USER",
    "SMTP_PASSWORD":                    "SMTP_PASSWORD",
    "SMTP_HOST":                        "SMTP_HOST",
    "SMTP_FROM":                        "SMTP_FROM",
    # Lowercase/dotted-path variants for alternate secret JSON structures
    "smtp_username":                    "SMTP_USER",
    "smtp_password":                    "SMTP_PASSWORD",
    "smtp_host":                        "SMTP_HOST",
    "smtp_from":                        "SMTP_FROM",
    "api.external.jira.smtp_username":  "SMTP_USER",
    "api.external.jira.smtp_password":  "SMTP_PASSWORD",
}


class AppConfig(BaseSettings):
    """Config from env; in prod overlay from AWS Secrets Manager."""

    app_name: str = "deepintel"
    env: str = Field(default="local", alias="ENV")
    debug: bool = Field(default=False, alias="DEBUG")

    # MongoDB (prod: from Secrets Manager)
    mongodb_uri: str = Field(
        default="mongodb://localhost:27017", alias="MONGODB_URI"
    )
    mongodb_db: str = Field(default="deepintel", alias="MONGODB_DB")

    # AWS (prod: from Secrets Manager)
    aws_region: str = Field(default="ap-south-1", alias="AWS_REGION")
    aws_secret_name: Optional[str] = Field(default=None, alias="AWS_SECRET_NAME")
    s3_raw_intel_bucket: Optional[str] = Field(default=None, alias="S3_RAW_INTEL_BUCKET")
    s3_audit_export_bucket: Optional[str] = Field(
        default=None, alias="S3_AUDIT_EXPORT_BUCKET"
    )

    # Gemini AI (prod: from Secrets Manager)
    gemini_api_key: Optional[str] = Field(default=None, alias="GEMINI_API_KEY")

    # LLM backend — "gemini" (default) or "ollama" (self-hosted DeepSeek-R1 etc.)
    llm_backend: str = Field(default="gemini", alias="LLM_BACKEND")
    local_llm_url: Optional[str] = Field(default=None, alias="LOCAL_LLM_URL")
    local_llm_model: str = Field(default="deepseek-r1:8b", alias="LOCAL_LLM_MODEL")

    # MDE (prod: from Secrets Manager)
    mde_tenant_id: Optional[str] = Field(default=None, alias="MDE_TENANT_ID")
    mde_client_id: Optional[str] = Field(default=None, alias="MDE_CLIENT_ID")
    mde_client_secret: Optional[str] = Field(default=None, alias="MDE_CLIENT_SECRET")

    # Cyble (prod: from Secrets Manager)
    cyble_api_token: Optional[str] = Field(default=None, alias="CYBLE_API_TOKEN")

    # Remote socket scanner (prod: private IP of scan EC2 in security account)
    socket_scan_api_url: Optional[str] = Field(default=None, alias="SOCKET_SCAN_API_URL")

    class Config:
        env_file = ".env"
        extra = "ignore"


def _resolve_secret(secrets: dict, dotted_key: str):
    """Resolve a secret value by dotted key, supporting both flat and nested JSON.

    Tries in order:
    1. Exact flat key (e.g. "api.external.jira.smtp_username" as a literal JSON key)
    2. Nested path traversal (e.g. secrets["api"]["external"]["jira"]["smtp_username"])
    3. Leaf-only key (the last segment after the last dot, e.g. "smtp_username")
    """
    # 1. Flat exact match
    val = secrets.get(dotted_key)
    if val:
        return val
    # 2. Nested path traversal
    parts = dotted_key.split(".")
    node = secrets
    for part in parts:
        if not isinstance(node, dict):
            node = None
            break
        node = node.get(part)
    if node and isinstance(node, str):
        return node
    # 3. Leaf-only fallback
    leaf = parts[-1]
    if leaf != dotted_key:
        return secrets.get(leaf)
    return None


_config: Optional[AppConfig] = None


def reset_config() -> None:
    """Clear cached config — useful after env changes or in tests."""
    global _config
    _config = None


def get_config() -> AppConfig:
    """Return config; in prod (ENV=prod) load from AWS Secrets Manager."""
    global _config
    if _config is not None:
        return _config

    region = os.getenv("AWS_REGION", "ap-south-1")
    # Set AWS_SECRET_NAME to pull config from AWS Secrets Manager; unset = env-only.
    secret_name = os.getenv("AWS_SECRET_NAME", "")

    if secret_name:
        try:
            import logging as _logging
            _logging.getLogger(__name__).warning("Loading secrets from: %s", secret_name)
            sm = SecretsManager()
            secrets = sm.get_secrets(secret_name, region)
            _logging.getLogger(__name__).warning("Secrets loaded — keys: %s", list(secrets.keys()))

            # Propagate every secret into os.environ so modules that call
            # os.getenv() directly (mde_client, cyble_ingestion, etc.) pick
            # up the values even if they were imported before get_config() ran.
            # _resolve_secret handles both flat keys and dotted nested paths.
            for secret_key, env_key in _SECRET_ENV_MAP.items():
                val = _resolve_secret(secrets, secret_key)
                if val:
                    os.environ[env_key] = str(val)

            overrides = {
                "aws_secret_name": secret_name,
                "mongodb_uri": secrets.get("mongodb_uri") or os.getenv("MONGODB_URI", "mongodb://localhost:27017"),
                "mongodb_db": secrets.get("mongodb_db") or os.getenv("MONGODB_DB", "deepintel"),
                "s3_raw_intel_bucket": secrets.get("s3_raw_intel_bucket") or os.getenv("S3_RAW_INTEL_BUCKET"),
                "s3_audit_export_bucket": secrets.get("s3_audit_export_bucket") or os.getenv("S3_AUDIT_EXPORT_BUCKET"),
                "aws_region": secrets.get("aws_region") or region,
                "gemini_api_key": secrets.get("gemini_api_key") or os.getenv("GEMINI_API_KEY"),
                "mde_tenant_id": secrets.get("mde_tenant_id") or os.getenv("MDE_TENANT_ID"),
                "mde_client_id": secrets.get("mde_client_id") or os.getenv("MDE_CLIENT_ID"),
                "mde_client_secret": secrets.get("mde_client_secret") or os.getenv("MDE_CLIENT_SECRET"),
                "cyble_api_token": secrets.get("cyble_api_token") or os.getenv("CYBLE_API_TOKEN"),
                "socket_scan_api_url": secrets.get("socket_scan_api_url") or os.getenv("SOCKET_SCAN_API_URL"),
            }
            _config = AppConfig(**{k: v for k, v in overrides.items() if v is not None})
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning(
                "Secrets Manager unavailable (%s) — falling back to env-based config", exc
            )
            _config = AppConfig()
    else:
        _config = AppConfig()

    return _config
