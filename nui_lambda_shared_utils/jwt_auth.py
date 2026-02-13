"""
JWT validation utilities for AWS Lambda functions behind API Gateway.

Uses RS256 signature verification with public keys stored in AWS Secrets Manager.
Requires the `rsa` package (pure Python, ~100KB) — no PyJWT or cryptography needed at runtime.

Install: pip install nui-lambda-shared-utils[jwt]
"""

import os
import json
import base64
import time
import logging
from typing import Optional

from .secrets_helper import get_secret

log = logging.getLogger(__name__)

_rsa = None


def _require_rsa():
    """Lazy-import the rsa package, raising a clear error if not installed."""
    global _rsa
    if _rsa is None:
        try:
            import rsa

            _rsa = rsa
        except ImportError:
            raise ImportError("The 'rsa' package is required for JWT support. Install with: pip install nui-lambda-shared-utils[jwt]")
    return _rsa


class JWTValidationError(Exception):
    """Base exception for JWT validation failures."""

    pass


class AuthenticationError(JWTValidationError):
    """Authentication failed — missing/invalid token or header."""

    pass


def get_jwt_public_key(secret_name: Optional[str] = None, key_field: str = "TOKEN_PUBLIC_KEY"):
    """
    Fetch PEM public key from AWS Secrets Manager and return as rsa.PublicKey.

    Relies on secrets_helper cache — repeated calls with the same secret_name
    do not make additional Secrets Manager API calls.

    Args:
        secret_name: Secrets Manager secret name. Falls back to JWT_PUBLIC_KEY_SECRET env var.
        key_field: JSON field containing the PEM-encoded public key.

    Returns:
        rsa.PublicKey ready for signature verification.

    Raises:
        JWTValidationError: If secret or key field is missing/invalid.
    """
    rsa = _require_rsa()

    secret_name = secret_name or os.environ.get("JWT_PUBLIC_KEY_SECRET")
    if not secret_name:
        raise JWTValidationError("No JWT public key secret name provided (set JWT_PUBLIC_KEY_SECRET or pass secret_name)")

    secret = get_secret(secret_name)

    pem_str = secret.get(key_field)
    if not pem_str:
        raise JWTValidationError(f"Field '{key_field}' not found in secret '{secret_name}'")

    try:
        return rsa.PublicKey.load_pkcs1_openssl_pem(pem_str.encode("utf-8"))
    except Exception as e:
        raise JWTValidationError(
            f"Failed to load public key from '{key_field}' — expected PKCS#8 PEM format (BEGIN PUBLIC KEY): {e}"
        ) from e


def _base64url_decode(data: str) -> bytes:
    """Decode base64url-encoded string (no padding required)."""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def validate_jwt(token: str, public_key) -> dict:
    """
    Decode and verify an RS256-signed JWT.

    Verifies:
    - Token structure (3 dot-separated segments)
    - Algorithm is RS256
    - RSA signature using the provided public key
    - Expiration (exp claim, if present)

    Args:
        token: Raw JWT string (without "Bearer " prefix).
        public_key: RSA public key for signature verification.

    Returns:
        Decoded claims dict (the JWT payload).

    Raises:
        JWTValidationError: On any structural, signature, or expiration failure.
    """
    rsa = _require_rsa()

    # Split into segments
    parts = token.split(".")
    if len(parts) != 3:
        raise JWTValidationError(f"Malformed JWT: expected 3 segments, got {len(parts)}")

    header_b64, payload_b64, signature_b64 = parts

    # Decode header and check algorithm
    try:
        header = json.loads(_base64url_decode(header_b64))
    except Exception as e:
        raise JWTValidationError(f"Invalid JWT header: {e}") from e

    alg = header.get("alg")
    if alg != "RS256":
        raise JWTValidationError(f"Unsupported algorithm '{alg}' — only RS256 is accepted")

    # Decode signature
    try:
        signature = _base64url_decode(signature_b64)
    except Exception as e:
        raise JWTValidationError(f"Invalid JWT signature encoding: {e}") from e

    # Verify RS256 signature over "<header_b64>.<payload_b64>"
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        hash_method = rsa.verify(signing_input, signature, public_key)
    except rsa.VerificationError:
        raise JWTValidationError("JWT signature verification failed") from None

    if hash_method != "SHA-256":
        raise JWTValidationError(f"Unexpected hash method '{hash_method}' — expected SHA-256 for RS256")

    # Decode payload
    try:
        claims = json.loads(_base64url_decode(payload_b64))
    except Exception as e:
        raise JWTValidationError(f"Invalid JWT payload: {e}") from e

    # Check expiration
    exp = claims.get("exp")
    if exp is not None and time.time() > exp:
        raise JWTValidationError("JWT has expired")

    return claims


def _extract_header(event: dict, header_name: str) -> Optional[str]:
    """Extract a header value from an API Gateway event (v1 or v2), case-insensitive."""
    headers = event.get("headers") or {}
    # API Gateway v2 (HTTP API) lowercases all header names
    # API Gateway v1 (REST) preserves original case
    for key, value in headers.items():
        if key.lower() == header_name.lower():
            return value
    return None


def require_auth(event: dict, secret_name: Optional[str] = None) -> dict:
    """
    Extract and validate a Bearer token from an API Gateway event.

    Handles both API Gateway v1 (REST) and v2 (HTTP API) event formats.

    Args:
        event: API Gateway Lambda proxy integration event.
        secret_name: Optional Secrets Manager secret name for the public key.

    Returns:
        Decoded JWT claims dict.

    Raises:
        AuthenticationError: If the Authorization header is missing, malformed, or token is invalid.
    """
    auth_header = _extract_header(event, "Authorization")
    if not auth_header:
        raise AuthenticationError("Missing Authorization header")

    if not auth_header.startswith("Bearer "):
        raise AuthenticationError("Authorization header must use Bearer scheme")

    token = auth_header[7:]  # len("Bearer ") == 7
    if not token:
        raise AuthenticationError("Empty Bearer token")

    try:
        public_key = get_jwt_public_key(secret_name=secret_name)
        return validate_jwt(token, public_key)
    except JWTValidationError as e:
        raise AuthenticationError(f"Authentication failed: {e}") from e
