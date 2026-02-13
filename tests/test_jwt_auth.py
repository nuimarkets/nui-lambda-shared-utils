"""Tests for JWT authentication module."""

import json
import time
import base64
import pytest
from typing import Optional
from unittest.mock import patch, Mock

from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa, padding
from cryptography.hazmat.primitives import hashes, serialization

import rsa as rsa_lib

from nui_lambda_shared_utils.jwt_auth import (
    validate_jwt,
    require_auth,
    get_jwt_public_key,
    JWTValidationError,
    AuthenticationError,
    _base64url_decode,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def rsa_keypair():
    """Generate an RSA key pair using cryptography (dev-only dependency).

    Returns (private_key, public_key_pem, rsa_public_key) where:
    - private_key: cryptography private key for signing test tokens
    - public_key_pem: PEM string for storage in mock secrets
    - rsa_public_key: rsa.PublicKey for direct use in validate_jwt()
    """
    private_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    rsa_public_key = rsa_lib.PublicKey.load_pkcs1_openssl_pem(public_key_pem.encode("utf-8"))
    return private_key, public_key_pem, rsa_public_key


@pytest.fixture
def second_rsa_keypair():
    """A second, different RSA key pair for wrong-key tests."""
    private_key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key


@pytest.fixture
def mock_jwt_secret(rsa_keypair, mock_secrets_manager):
    """Configure mock Secrets Manager to return the test public key PEM."""
    _, public_key_pem, _ = rsa_keypair
    mock_secrets_manager.get_secret_value.return_value = {
        "SecretString": json.dumps({"TOKEN_PUBLIC_KEY": public_key_pem})
    }
    return mock_secrets_manager


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_jwt(private_key, claims: dict, header: Optional[dict] = None) -> str:
    """Create an RS256-signed JWT using the cryptography library."""
    if header is None:
        header = {"alg": "RS256", "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header).encode())
    payload_b64 = _b64url_encode(json.dumps(claims).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    signature_b64 = _b64url_encode(signature)
    return f"{header_b64}.{payload_b64}.{signature_b64}"


# ---------------------------------------------------------------------------
# validate_jwt tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestValidateJwt:
    def test_valid_token(self, rsa_keypair):
        """RS256 sign + verify round-trip succeeds."""
        private_key, _, public_key = rsa_keypair
        claims = {"sub": "user123", "exp": time.time() + 3600, "role": "admin"}
        token = _sign_jwt(private_key, claims)

        result = validate_jwt(token, public_key)

        assert result["sub"] == "user123"
        assert result["role"] == "admin"

    def test_expired_token(self, rsa_keypair):
        """Token with past exp claim is rejected."""
        private_key, _, public_key = rsa_keypair
        claims = {"sub": "user123", "exp": time.time() - 60}
        token = _sign_jwt(private_key, claims)

        with pytest.raises(JWTValidationError, match="expired"):
            validate_jwt(token, public_key)

    def test_invalid_signature(self, rsa_keypair, second_rsa_keypair):
        """Token signed with a different key is rejected."""
        wrong_key = second_rsa_keypair
        _, _, public_key = rsa_keypair
        claims = {"sub": "user123", "exp": time.time() + 3600}
        token = _sign_jwt(wrong_key, claims)

        with pytest.raises(JWTValidationError, match="signature verification failed"):
            validate_jwt(token, public_key)

    def test_wrong_algorithm(self, rsa_keypair):
        """Token with alg != RS256 is rejected before signature verification."""
        private_key, _, public_key = rsa_keypair
        claims = {"sub": "user123"}
        token = _sign_jwt(private_key, claims, header={"alg": "HS256", "typ": "JWT"})

        with pytest.raises(JWTValidationError, match=r"Unsupported algorithm.*HS256"):
            validate_jwt(token, public_key)

    def test_malformed_token_missing_segments(self, rsa_keypair):
        """Token with wrong number of segments raises JWTValidationError."""
        _, _, public_key = rsa_keypair

        with pytest.raises(JWTValidationError, match="expected 3 segments"):
            validate_jwt("only.two", public_key)

        with pytest.raises(JWTValidationError, match="expected 3 segments"):
            validate_jwt("nosegments", public_key)

    def test_malformed_token_bad_base64(self, rsa_keypair):
        """Token with invalid base64 in header raises JWTValidationError."""
        _, _, public_key = rsa_keypair

        with pytest.raises(JWTValidationError, match="Invalid JWT header"):
            validate_jwt("!!!.payload.sig", public_key)

    def test_no_exp_claim_accepted(self, rsa_keypair):
        """Token without exp claim is accepted (exp is optional)."""
        private_key, _, public_key = rsa_keypair
        claims = {"sub": "service-account", "scope": "internal"}
        token = _sign_jwt(private_key, claims)

        result = validate_jwt(token, public_key)
        assert result["sub"] == "service-account"


# ---------------------------------------------------------------------------
# require_auth tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestRequireAuth:
    def test_valid_header(self, rsa_keypair, mock_jwt_secret):
        """Authorization: Bearer <token> is extracted and validated."""
        private_key, _, _ = rsa_keypair
        claims = {"sub": "user123", "exp": time.time() + 3600}
        token = _sign_jwt(private_key, claims)

        event = {"headers": {"Authorization": f"Bearer {token}"}}
        with patch.dict("os.environ", {"JWT_PUBLIC_KEY_SECRET": "test/jwt-key"}):
            result = require_auth(event)

        assert result["sub"] == "user123"

    def test_missing_header(self):
        """No Authorization header raises AuthenticationError."""
        event = {"headers": {}}
        with pytest.raises(AuthenticationError, match="Missing Authorization header"):
            require_auth(event)

    def test_missing_headers_key(self):
        """Event with no headers key raises AuthenticationError."""
        event = {}
        with pytest.raises(AuthenticationError, match="Missing Authorization header"):
            require_auth(event)

    def test_malformed_header_basic(self):
        """Authorization: Basic ... raises AuthenticationError."""
        event = {"headers": {"Authorization": "Basic dXNlcjpwYXNz"}}
        with pytest.raises(AuthenticationError, match="Bearer scheme"):
            require_auth(event)

    def test_empty_bearer(self):
        """Authorization: Bearer (no token) raises AuthenticationError."""
        event = {"headers": {"Authorization": "Bearer "}}
        with pytest.raises(AuthenticationError, match="Empty Bearer token"):
            require_auth(event)

    def test_case_insensitive_header(self, rsa_keypair, mock_jwt_secret):
        """Lowercase 'authorization' header works (API Gateway v2)."""
        private_key, _, _ = rsa_keypair
        claims = {"sub": "user456", "exp": time.time() + 3600}
        token = _sign_jwt(private_key, claims)

        event = {"headers": {"authorization": f"Bearer {token}"}}
        with patch.dict("os.environ", {"JWT_PUBLIC_KEY_SECRET": "test/jwt-key"}):
            result = require_auth(event)

        assert result["sub"] == "user456"


# ---------------------------------------------------------------------------
# get_jwt_public_key tests
# ---------------------------------------------------------------------------


@pytest.mark.unit
class TestGetJwtPublicKey:
    def test_caching_via_secrets_helper(self, mock_jwt_secret):
        """get_secret() is called once for multiple key fetches (secrets_helper cache)."""
        key1 = get_jwt_public_key(secret_name="test/jwt-key")
        key2 = get_jwt_public_key(secret_name="test/jwt-key")

        assert key1 == key2
        # get_secret_value should only be called once due to _secrets_cache
        mock_jwt_secret.get_secret_value.assert_called_once()

    def test_from_env_var(self, mock_jwt_secret):
        """JWT_PUBLIC_KEY_SECRET env var used as default secret name."""
        with patch.dict("os.environ", {"JWT_PUBLIC_KEY_SECRET": "env/jwt-key"}):
            key = get_jwt_public_key()

        assert isinstance(key, rsa_lib.PublicKey)
        mock_jwt_secret.get_secret_value.assert_called_once_with(SecretId="env/jwt-key")

    def test_no_secret_name_raises(self):
        """Missing secret name (no param, no env var) raises JWTValidationError."""
        with patch.dict("os.environ", {}, clear=True):
            with pytest.raises(JWTValidationError, match="No JWT public key secret name"):
                get_jwt_public_key()

    def test_missing_key_field_raises(self, mock_secrets_manager):
        """Secret exists but missing the expected key field raises JWTValidationError."""
        mock_secrets_manager.get_secret_value.return_value = {
            "SecretString": json.dumps({"OTHER_FIELD": "some_value"})
        }

        with pytest.raises(JWTValidationError, match="Field 'TOKEN_PUBLIC_KEY' not found"):
            get_jwt_public_key(secret_name="test/jwt-key")
