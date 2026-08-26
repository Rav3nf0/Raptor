"""
S3 handler — strategic lib.
Read/write JSON, file_exists, delete_file. Used for raw intel storage and audit export.
"""
import logging
import traceback
import json
import boto3
from botocore.exceptions import ClientError
from typing import Optional, Dict, Any


class S3Handler:
    def __init__(self, region_name: Optional[str] = None):
        self.logger = logging.getLogger(__name__)
        self.region_name = region_name or "ap-south-1"
        self.s3_client = boto3.client("s3", region_name=self.region_name)

    def read_json(self, bucket_name: str, key: str) -> Optional[Dict[str, Any]]:
        try:
            response = self.s3_client.get_object(Bucket=bucket_name, Key=key)
            content = response["Body"].read().decode("utf-8")
            return json.loads(content)
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code == "NoSuchKey":
                self.logger.warning("File not found: s3://%s/%s", bucket_name, key)
                return None
            if code == "NoSuchBucket":
                self.logger.error("Bucket not found: %s", bucket_name)
            raise e
        except json.JSONDecodeError as e:
            self.logger.error("Invalid JSON s3://%s/%s: %s", bucket_name, key, e)
            raise e
        except Exception as e:
            self.logger.error(traceback.format_exc())
            raise e

    def write_json(
        self,
        bucket_name: str,
        key: str,
        data: Dict[str, Any],
        content_type: str = "application/json",
    ) -> bool:
        try:
            body = json.dumps(data, indent=2, ensure_ascii=False).encode("utf-8")
            self.s3_client.put_object(
                Bucket=bucket_name, Key=key, Body=body, ContentType=content_type
            )
            self.logger.info("Wrote s3://%s/%s", bucket_name, key)
            return True
        except ClientError as e:
            self.logger.error("Error writing to S3: %s", e)
            raise e
        except Exception as e:
            self.logger.error(traceback.format_exc())
            raise e

    def file_exists(self, bucket_name: str, key: str) -> bool:
        try:
            self.s3_client.head_object(Bucket=bucket_name, Key=key)
            return True
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") in ("404", "NoSuchKey"):
                return False
            raise e
        except Exception as e:
            self.logger.error(traceback.format_exc())
            raise e

    def delete_file(self, bucket_name: str, key: str) -> bool:
        try:
            self.s3_client.delete_object(Bucket=bucket_name, Key=key)
            self.logger.info("Deleted s3://%s/%s", bucket_name, key)
            return True
        except ClientError as e:
            self.logger.error("Error deleting from S3: %s", e)
            raise e
        except Exception as e:
            self.logger.error(traceback.format_exc())
            raise e
