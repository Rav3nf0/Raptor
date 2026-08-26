"""
AWS Secrets Manager — strategic lib.
Use get_secrets(secret_name, region_name); secret value should be a JSON-compatible string.
"""
import logging
import traceback
import json
import boto3
from botocore.exceptions import ClientError

from typing import Any


class SecretsManager:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def get_secrets(self, secret_name: str, region_name: str) -> dict[str, Any]:
        session = boto3.session.Session()
        client = session.client(
            service_name="secretsmanager", region_name=region_name
        )
        try:
            response = client.get_secret_value(SecretId=secret_name)
            if "SecretString" in response:
                raw = response["SecretString"]
                try:
                    return json.loads(raw)
                except json.JSONDecodeError:
                    import ast
                    return ast.literal_eval(raw)
            else:
                import base64
                return {"SecretBinary": base64.b64decode(response["SecretBinary"])}
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            self.logger.error("Secrets Manager error: %s", code)
            raise e
        except Exception as e:
            self.logger.error(traceback.format_exc())
            raise e

    def jira_credentials(
        self, secret_name: str, region_name: str = "ap-south-1"
    ) -> tuple[str, str]:
        """Return (jira_email, jira_api_token) from Secrets Manager.

        The secret JSON must contain keys ``jira_email`` and ``jira_api_token``.
        """
        secrets = self.get_secrets(secret_name, region_name)
        email = secrets.get("jira_email", "")
        token = secrets.get("jira_api_token", "")
        if not email or not token:
            raise ValueError(
                f"Secret '{secret_name}' is missing 'jira_email' or 'jira_api_token'"
            )
        return email, token
