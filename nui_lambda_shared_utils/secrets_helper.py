"""
AWS Secrets Manager helper for retrieving credentials.
Shared across all AWS Lambda functions.
"""

import os
import json
import logging
from typing import Dict, Optional
import boto3
from botocore.exceptions import ClientError

from .config import get_config

log = logging.getLogger(__name__)

# Cache for secrets to avoid repeated API calls
_secrets_cache = {}


def get_secret(secret_name: str) -> Dict:
    """
    Retrieve secret from AWS Secrets Manager.

    Args:
        secret_name: Name of the secret in Secrets Manager

    Returns:
        Dict containing the secret values

    Raises:
        Exception if secret cannot be retrieved
    """
    # Check cache first
    if secret_name in _secrets_cache:
        return _secrets_cache[secret_name]

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(service_name="secretsmanager", region_name=session.region_name or "ap-southeast-2")

    try:
        response = client.get_secret_value(SecretId=secret_name)

        # Secrets Manager stores either a string or binary
        if "SecretString" in response:
            secret = json.loads(response["SecretString"])
        else:
            # Binary secret (not typically used for credentials)
            secret = json.loads(response["SecretBinary"].decode("utf-8"))

        # Cache the secret
        _secrets_cache[secret_name] = secret

        log.info(f"Successfully retrieved secret: {secret_name}")
        return secret

    except ClientError as e:
        error_code = e.response["Error"]["Code"]

        if error_code == "DecryptionFailureException":
            log.error(f"Cannot decrypt secret {secret_name}: {e}")
            raise Exception(f"Cannot decrypt secret {secret_name}")
        elif error_code == "InternalServiceErrorException":
            log.error(f"Internal service error retrieving {secret_name}: {e}")
            raise Exception(f"Internal service error retrieving {secret_name}")
        elif error_code == "InvalidParameterException":
            log.error(f"Invalid parameter for {secret_name}: {e}")
            raise Exception(f"Invalid parameter for {secret_name}")
        elif error_code == "InvalidRequestException":
            log.error(f"Invalid request for {secret_name}: {e}")
            raise Exception(f"Invalid request for {secret_name}")
        elif error_code == "ResourceNotFoundException":
            log.error(f"Secret {secret_name} not found: {e}")
            raise Exception(f"Secret {secret_name} not found")
        else:
            log.error(f"Unknown error retrieving {secret_name}: {e}")
            raise Exception(f"Error retrieving secret {secret_name}: {error_code}")
    except Exception as e:
        log.error(f"Unexpected error retrieving {secret_name}: {e}")
        raise Exception(f"Unexpected error retrieving secret {secret_name}: {str(e)}")


def get_database_credentials(secret_name: Optional[str] = None) -> Dict:
    """
    Get database credentials with standardized field names.

    Args:
        secret_name: Override default from configuration or environment

    Returns:
        Dict with host, port, username, password, database
    """
    config = get_config()
    secret = secret_name or os.environ.get("DB_CREDENTIALS_SECRET") or config.db_credentials_secret
    if not secret:
        raise ValueError("No database secret name provided")

    creds = get_secret(secret)

    # Normalize field names
    return {
        "host": creds.get("host", creds.get("endpoint", creds.get("hostname"))),
        "port": int(creds.get("port", 3306)),
        "username": creds.get("username", creds.get("user")),
        "password": creds.get("password"),
        "database": creds.get("database", creds.get("dbname", "app")),
    }


def get_elasticsearch_credentials(secret_name: Optional[str] = None) -> Dict:
    """
    Get Elasticsearch credentials.

    Args:
        secret_name: Override default from configuration or environment

    Returns:
        Dict with host, username, password
    """
    config = get_config()
    secret = secret_name or os.environ.get("ES_CREDENTIALS_SECRET") or config.es_credentials_secret
    if not secret:
        raise ValueError("No Elasticsearch secret name provided")

    creds = get_secret(secret)

    # Use configuration system for host defaults instead of hardcoded value
    host = os.environ.get("ES_HOST") or creds.get("host") or config.es_host
    # Ensure port is included if not already present
    if ":" not in host and not host.startswith("http"):
        host = f"{host}:9200"

    return {
        "host": host,
        "username": creds.get("username", "elastic"),
        "password": creds.get("password"),
    }


def get_slack_credentials(secret_name: Optional[str] = None) -> Dict:
    """
    Get Slack bot credentials.

    Args:
        secret_name: Override default from configuration or environment

    Returns:
        Dict with bot_token and optional webhook_url
    """
    config = get_config()
    secret = secret_name or os.environ.get("SLACK_CREDENTIALS_SECRET") or config.slack_credentials_secret
    if not secret:
        raise ValueError("No Slack secret name provided")

    creds = get_secret(secret)

    return {
        "bot_token": creds.get("bot_token", creds.get("token")),
        "webhook_url": creds.get("webhook_url"),  # Optional
    }


def get_api_key(secret_name: str, key_field: str = "api_key") -> str:
    """
    Get a simple API key from secrets.

    Args:
        secret_name: Name of the secret
        key_field: Field name containing the key (default: 'api_key')

    Returns:
        The API key string
    """
    secret = get_secret(secret_name)

    if key_field not in secret:
        raise KeyError(f"Field '{key_field}' not found in secret {secret_name}")

    return secret[key_field]


def clear_cache() -> None:
    """Clear the secrets cache. Useful for long-running Lambdas."""
    global _secrets_cache
    _secrets_cache.clear()
    log.info("Cleared secrets cache")
