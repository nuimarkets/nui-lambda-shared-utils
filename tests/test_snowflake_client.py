"""Tests for the NUI Snowflake adapter (nui_shared_utils.snowflake_client).

Covers credential resolution (explicit / env / Secrets Manager via moto),
NUI session defaults, the redacting query-logging hook, sync + async client
construction, and the clear-error path when the optional extra is missing.
"""

import json
import logging
import os

import boto3
import pytest
from moto import mock_aws

from nui_shared_utils import snowflake_client as sc

# All tests here are fast and offline (moto mocks Secrets Manager in-process;
# "real" client construction only parses a local key, no network). Mark the
# module ``unit`` to match the rest of the suite.
pytestmark = pytest.mark.unit

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_private_key_pem() -> bytes:
    """A real unencrypted RSA private key (PEM) for end-to-end construction."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )


@pytest.fixture
def aws_env(monkeypatch):
    """Dummy AWS env so boto3/moto have a region and credentials."""
    monkeypatch.setenv("AWS_DEFAULT_REGION", "ap-southeast-2")
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")


@pytest.fixture
def clear_snowflake_env(monkeypatch):
    """Ensure SNOWFLAKE_* env does not leak between tests."""
    for var in (
        "SNOWFLAKE_ACCOUNT",
        "SNOWFLAKE_USER",
        "SNOWFLAKE_PRIVATE_KEY",
        "SNOWFLAKE_PRIVATE_KEY_PATH",
        "SNOWFLAKE_PRIVATE_KEY_PASSPHRASE",
        "SNOWFLAKE_CREDENTIALS_SECRET",
    ):
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def secret_in_sm(aws_env, rsa_private_key_pem):
    """Create a Snowflake credentials secret in a mocked Secrets Manager."""
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="ap-southeast-2")
        client.create_secret(
            Name="snowflake-credentials",
            SecretString=json.dumps(
                {
                    "account": "bj72353.ap-southeast-2",
                    "user": "NUI_SVC",
                    "private_key": rsa_private_key_pem.decode("utf-8"),
                }
            ),
        )
        yield "snowflake-credentials"


# ---------------------------------------------------------------------------
# get_snowflake_credentials
# ---------------------------------------------------------------------------


class TestGetCredentials:
    def test_explicit_args_skip_secrets_manager(self, clear_snowflake_env, mocker, rsa_private_key_pem):
        spy = mocker.patch("nui_shared_utils.secrets_helper.get_secret")
        creds = sc.get_snowflake_credentials(
            account="ab12345",
            user="tim",
            private_key=rsa_private_key_pem,
            private_key_passphrase="hunter2",
        )
        assert creds["account"] == "ab12345"
        assert creds["user"] == "tim"
        assert creds["private_key"] == rsa_private_key_pem
        assert creds["private_key_passphrase"] == "hunter2"
        spy.assert_not_called()

    def test_explicit_string_key_coerced_to_bytes(self, clear_snowflake_env, rsa_private_key_pem):
        creds = sc.get_snowflake_credentials(
            account="ab12345",
            user="tim",
            private_key=rsa_private_key_pem.decode("utf-8"),
        )
        assert creds["private_key"] == rsa_private_key_pem

    def test_env_inline_key(self, clear_snowflake_env, monkeypatch, mocker, rsa_private_key_pem):
        spy = mocker.patch("nui_shared_utils.secrets_helper.get_secret")
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345.ap-southeast-2")
        monkeypatch.setenv("SNOWFLAKE_USER", "env_user")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_key_pem.decode("utf-8"))
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "pp")
        creds = sc.get_snowflake_credentials()
        assert creds["account"] == "ab12345.ap-southeast-2"
        assert creds["user"] == "env_user"
        assert creds["private_key"] == rsa_private_key_pem
        assert creds["private_key_passphrase"] == "pp"
        spy.assert_not_called()

    def test_explicit_key_wins_over_stale_env_key(self, clear_snowflake_env, monkeypatch, mocker, rsa_private_key_pem):
        """Regression (codex #1): explicit key must beat env, never silently swapped."""
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        stale = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        assert stale != rsa_private_key_pem
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "env_acct")
        monkeypatch.setenv("SNOWFLAKE_USER", "env_user")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", stale.decode("utf-8"))
        spy = mocker.patch("nui_shared_utils.secrets_helper.get_secret")
        creds = sc.get_snowflake_credentials(private_key=rsa_private_key_pem)
        # Explicit key wins; account/user fall through to env.
        assert creds["private_key"] == rsa_private_key_pem
        assert creds["account"] == "env_acct"
        assert creds["user"] == "env_user"
        spy.assert_not_called()

    def test_explicit_key_not_paired_with_stale_env_passphrase(
        self, clear_snowflake_env, monkeypatch, rsa_private_key_pem
    ):
        """An explicit (unencrypted) key must not pick up a stale env passphrase."""
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "env_acct")
        monkeypatch.setenv("SNOWFLAKE_USER", "env_user")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "stale-env-pp")
        creds = sc.get_snowflake_credentials(account="a", user="u", private_key=rsa_private_key_pem)
        assert creds["private_key_passphrase"] is None

    def test_explicit_passphrase_arg_wins_over_env(self, clear_snowflake_env, monkeypatch, rsa_private_key_pem):
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345")
        monkeypatch.setenv("SNOWFLAKE_USER", "env_user")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY", rsa_private_key_pem.decode("utf-8"))
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "env-pp")
        creds = sc.get_snowflake_credentials(private_key_passphrase="arg-pp")
        assert creds["private_key_passphrase"] == "arg-pp"

    def test_invalid_key_type_raises(self, clear_snowflake_env):
        with pytest.raises(ValueError, match="PEM text"):
            sc.get_snowflake_credentials(account="a", user="u", private_key=12345)

    def test_empty_explicit_key_raises(self, clear_snowflake_env, mocker):
        """An empty explicit key must not slip past validation (codex finding)."""
        spy = mocker.patch("nui_shared_utils.secrets_helper.get_secret")
        with pytest.raises(ValueError, match="non-empty private_key"):
            sc.get_snowflake_credentials(account="a", user="u", private_key=b"")
        # account+user present, so the empty key must be caught without an SM call.
        spy.assert_not_called()

    def test_env_passphrase_not_used_when_key_from_secret(
        self, clear_snowflake_env, monkeypatch, mocker, rsa_private_key_pem
    ):
        """A secret-sourced key pairs with the secret passphrase, not a stale env one."""
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "stale-env-pp")
        mocker.patch(
            "nui_shared_utils.secrets_helper.get_secret",
            return_value={
                "account": "ab12345",
                "user": "svc",
                "private_key": rsa_private_key_pem.decode("utf-8"),
                "private_key_passphrase": "secret-pp",
            },
        )
        creds = sc.get_snowflake_credentials("some-secret")
        assert creds["private_key_passphrase"] == "secret-pp"

    def test_env_key_path(self, clear_snowflake_env, monkeypatch, tmp_path, rsa_private_key_pem):
        key_file = tmp_path / "snowflake.p8"
        key_file.write_bytes(rsa_private_key_pem)
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345")
        monkeypatch.setenv("SNOWFLAKE_USER", "env_user")
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PATH", str(key_file))
        monkeypatch.setenv("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE", "filepp")
        creds = sc.get_snowflake_credentials()
        assert creds["private_key"] == rsa_private_key_pem
        # Env key-path pairs with the env passphrase from the same tier.
        assert creds["private_key_passphrase"] == "filepp"

    def test_env_requires_account_user_and_key(self, clear_snowflake_env, monkeypatch, mocker):
        # Only account+user but no key -> falls through to Secrets Manager.
        monkeypatch.setenv("SNOWFLAKE_ACCOUNT", "ab12345")
        monkeypatch.setenv("SNOWFLAKE_USER", "env_user")
        spy = mocker.patch(
            "nui_shared_utils.secrets_helper.get_secret",
            return_value={"account": "x", "user": "y", "private_key": "PEMDATA"},
        )
        sc.get_snowflake_credentials()
        spy.assert_called_once()

    def test_secrets_manager(self, clear_snowflake_env, secret_in_sm, rsa_private_key_pem):
        # secret_in_sm fixture creates the secret in a live moto context.
        creds = sc.get_snowflake_credentials(secret_in_sm)
        assert creds["account"] == "bj72353.ap-southeast-2"
        assert creds["user"] == "NUI_SVC"
        assert creds["private_key"] == rsa_private_key_pem
        assert creds["private_key_passphrase"] is None

    def test_secrets_manager_field_aliases(self, clear_snowflake_env, aws_env, mocker, rsa_private_key_pem):
        mocker.patch(
            "nui_shared_utils.secrets_helper.get_secret",
            return_value={
                "snowflake_account": "ab12345",
                "username": "aliased_user",
                "privateKey": rsa_private_key_pem.decode("utf-8"),
                "passphrase": "secretpp",
            },
        )
        creds = sc.get_snowflake_credentials("some-secret")
        assert creds["account"] == "ab12345"
        assert creds["user"] == "aliased_user"
        assert creds["private_key"] == rsa_private_key_pem
        assert creds["private_key_passphrase"] == "secretpp"

    def test_explicit_account_user_override_secret(self, clear_snowflake_env, mocker, rsa_private_key_pem):
        mocker.patch(
            "nui_shared_utils.secrets_helper.get_secret",
            return_value={
                "account": "secret_account",
                "user": "secret_user",
                "private_key": rsa_private_key_pem.decode("utf-8"),
            },
        )
        creds = sc.get_snowflake_credentials("some-secret", account="override_acct", user="override_user")
        assert creds["account"] == "override_acct"
        assert creds["user"] == "override_user"

    def test_missing_field_raises_naming_secret_not_contents(self, clear_snowflake_env, mocker, rsa_private_key_pem):
        mocker.patch(
            "nui_shared_utils.secrets_helper.get_secret",
            return_value={"account": "ab12345"},  # no user, no private_key
        )
        with pytest.raises(ValueError) as exc:
            sc.get_snowflake_credentials("my-snowflake-secret")
        msg = str(exc.value)
        assert "my-snowflake-secret" in msg
        assert "user" in msg and "private_key" in msg
        # Must not leak any key material in the error.
        assert "BEGIN" not in msg

    def test_secret_name_precedence(self, clear_snowflake_env, monkeypatch, mocker, rsa_private_key_pem):
        captured = {}

        def fake_get_secret(name):
            captured["name"] = name
            return {"account": "a", "user": "u", "private_key": rsa_private_key_pem.decode("utf-8")}

        mocker.patch("nui_shared_utils.secrets_helper.get_secret", side_effect=fake_get_secret)

        # Default
        sc.get_snowflake_credentials()
        assert captured["name"] == "snowflake-credentials"
        # Env override
        monkeypatch.setenv("SNOWFLAKE_CREDENTIALS_SECRET", "env-secret")
        sc.get_snowflake_credentials()
        assert captured["name"] == "env-secret"
        # Explicit arg wins
        sc.get_snowflake_credentials("explicit-secret")
        assert captured["name"] == "explicit-secret"


# ---------------------------------------------------------------------------
# redacting_query_logger
# ---------------------------------------------------------------------------


class TestRedactingLogger:
    def test_logs_sql_and_param_count_not_values(self, caplog):
        logger = logging.getLogger("nui_shared_utils.snowflake_client")
        hook = sc.redacting_query_logger(logger, level=logging.INFO)
        with caplog.at_level(logging.INFO, logger="nui_shared_utils.snowflake_client"):
            hook("SELECT * FROM orders WHERE id = ?", ["super-secret-pii-value"])
        records = [r for r in caplog.records if r.message == "snowflake query"]
        assert len(records) == 1
        rec = records[0]
        assert rec.sql == "SELECT * FROM orders WHERE id = ?"
        assert rec.bind_param_count == 1
        # The actual bind value must never appear anywhere in the log output.
        assert "super-secret-pii-value" not in caplog.text

    def test_param_count_zero_for_none(self, caplog):
        hook = sc.redacting_query_logger(level=logging.INFO)
        with caplog.at_level(logging.INFO, logger="nui_shared_utils.snowflake_client"):
            hook("SELECT 1", None)
        rec = [r for r in caplog.records if r.message == "snowflake query"][0]
        assert rec.bind_param_count == 0

    def test_sql_truncated(self, caplog):
        hook = sc.redacting_query_logger(level=logging.INFO, max_sql_chars=10)
        with caplog.at_level(logging.INFO, logger="nui_shared_utils.snowflake_client"):
            hook("SELECT " + "x" * 100, None)
        rec = [r for r in caplog.records if r.message == "snowflake query"][0]
        assert rec.sql.endswith("...(truncated)")
        assert len(rec.sql) == len("...(truncated)") + 10


# ---------------------------------------------------------------------------
# create_snowflake_client / create_async_snowflake_client
# ---------------------------------------------------------------------------


class TestCreateClient:
    @pytest.fixture
    def spy_client(self, mocker):
        return mocker.patch("nui_shared_utils.snowflake_client.SnowflakeClient")

    @pytest.fixture
    def spy_async_client(self, mocker):
        return mocker.patch("nui_shared_utils.snowflake_client.AsyncSnowflakeClient")

    def _base_kwargs(self, rsa_private_key_pem):
        return {"account": "ab12345", "user": "tim", "private_key": rsa_private_key_pem}

    def test_nui_defaults_applied(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sc.create_snowflake_client(**self._base_kwargs(rsa_private_key_pem))
        kwargs = spy_client.call_args.kwargs
        assert kwargs["timezone"] == "Pacific/Auckland"
        assert kwargs["role"] == "NUI_LAMBDA"
        # No session parameters are injected by default (WEEK_START is rejected
        # by the SQL API; TIMEZONE rides the dedicated `timezone` arg).
        assert kwargs["parameters"] is None
        assert kwargs["user_agent"] == "nui-python-shared-utils-snowflake"
        # Default on_query is the redacting hook.
        assert callable(kwargs["on_query"])

    def test_defaults_overridable(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sc.create_snowflake_client(
            role="ANALYST",
            timezone="UTC",
            warehouse="WH",
            database="DB",
            schema="SCH",
            **self._base_kwargs(rsa_private_key_pem),
        )
        kwargs = spy_client.call_args.kwargs
        assert kwargs["role"] == "ANALYST"
        assert kwargs["timezone"] == "UTC"
        assert kwargs["warehouse"] == "WH"
        assert kwargs["database"] == "DB"
        assert kwargs["schema"] == "SCH"

    def test_caller_parameters_passthrough(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sc.create_snowflake_client(
            parameters={"QUERY_TAG": "nui", "DATE_OUTPUT_FORMAT": "YYYY-MM-DD"},
            **self._base_kwargs(rsa_private_key_pem),
        )
        params = spy_client.call_args.kwargs["parameters"]
        assert params == {"QUERY_TAG": "nui", "DATE_OUTPUT_FORMAT": "YYYY-MM-DD"}

    def test_log_queries_false_disables_hook(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sc.create_snowflake_client(log_queries=False, **self._base_kwargs(rsa_private_key_pem))
        assert spy_client.call_args.kwargs["on_query"] is None

    def test_custom_on_query_overrides(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sentinel = lambda sql, params: None  # noqa: E731
        sc.create_snowflake_client(on_query=sentinel, **self._base_kwargs(rsa_private_key_pem))
        assert spy_client.call_args.kwargs["on_query"] is sentinel

    def test_client_kwargs_passthrough(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sc.create_snowflake_client(
            statement_timeout=120,
            timeout=30.0,
            host="custom.example.com",
            **self._base_kwargs(rsa_private_key_pem),
        )
        kwargs = spy_client.call_args.kwargs
        assert kwargs["statement_timeout"] == 120
        assert kwargs["timeout"] == 30.0
        assert kwargs["host"] == "custom.example.com"

    def test_custom_user_agent(self, clear_snowflake_env, spy_client, rsa_private_key_pem):
        sc.create_snowflake_client(user_agent="my-lambda/1.0", **self._base_kwargs(rsa_private_key_pem))
        assert spy_client.call_args.kwargs["user_agent"] == "my-lambda/1.0"

    def test_async_factory_applies_defaults(self, clear_snowflake_env, spy_async_client, rsa_private_key_pem):
        sc.create_async_snowflake_client(**self._base_kwargs(rsa_private_key_pem))
        kwargs = spy_async_client.call_args.kwargs
        assert kwargs["timezone"] == "Pacific/Auckland"
        assert kwargs["role"] == "NUI_LAMBDA"
        assert kwargs["parameters"] is None
        assert callable(kwargs["on_query"])

    def test_async_factory_full_parity(self, clear_snowflake_env, spy_async_client, rsa_private_key_pem):
        """Async factory must assemble the same kwargs as sync for a custom config."""
        sc.create_async_snowflake_client(
            role="ANALYST",
            timezone="UTC",
            warehouse="WH",
            database="DB",
            schema="SCH",
            parameters={"QUERY_TAG": "nui"},
            user_agent="my-lambda/1.0",
            log_queries=False,
            statement_timeout=120,
            host="custom.example.com",
            **self._base_kwargs(rsa_private_key_pem),
        )
        kwargs = spy_async_client.call_args.kwargs
        assert kwargs["role"] == "ANALYST"
        assert kwargs["timezone"] == "UTC"
        assert kwargs["warehouse"] == "WH"
        assert kwargs["database"] == "DB"
        assert kwargs["schema"] == "SCH"
        assert kwargs["parameters"] == {"QUERY_TAG": "nui"}
        assert kwargs["user_agent"] == "my-lambda/1.0"
        assert kwargs["on_query"] is None
        assert kwargs["statement_timeout"] == 120
        assert kwargs["host"] == "custom.example.com"

    def test_parameters_dict_is_copied(self, clear_snowflake_env, rsa_private_key_pem):
        """Mutating the caller's parameters dict must not affect the client."""
        params = {"QUERY_TAG": "original"}
        client = sc.create_snowflake_client(parameters=params, **self._base_kwargs(rsa_private_key_pem))
        try:
            params["QUERY_TAG"] = "mutated"
            params["EXTRA"] = "added"
            assert client._parameters == {"QUERY_TAG": "original"}
        finally:
            client.close()

    def test_real_sync_client_constructs(self, clear_snowflake_env, rsa_private_key_pem):
        """End-to-end: a real SnowflakeClient is built (key parsed, no network)."""
        from snowflake_sql_api import SnowflakeClient

        client = sc.create_snowflake_client(
            account="ab12345.ap-southeast-2",
            user="tim",
            private_key=rsa_private_key_pem,
        )
        try:
            assert isinstance(client, SnowflakeClient)
            assert client.role == "NUI_LAMBDA"
            assert client.timezone == "Pacific/Auckland"
            assert client._parameters == {}
            assert client.on_query is not None
        finally:
            client.close()

    def test_real_async_client_constructs(self, clear_snowflake_env, rsa_private_key_pem):
        import asyncio

        from snowflake_sql_api import AsyncSnowflakeClient

        client = sc.create_async_snowflake_client(
            account="ab12345.ap-southeast-2",
            user="tim",
            private_key=rsa_private_key_pem,
        )
        try:
            assert isinstance(client, AsyncSnowflakeClient)
            assert client.role == "NUI_LAMBDA"
            assert client.timezone == "Pacific/Auckland"
        finally:
            asyncio.run(client.aclose())

    def test_async_factory_queries_through_fake_snowflake(self, clear_snowflake_env, rsa_private_key_pem):
        """Offline smoke path: shared-utils async factory can run a real query."""
        import asyncio

        import httpx
        from snowflake_sql_api.testing import FakeSnowflake

        async def run_query():
            fake = FakeSnowflake()
            fake.register(
                "SELECT id, payload FROM events WHERE kind = ?",
                [{"id": 1, "payload": {"ok": True}}],
            )
            async with httpx.AsyncClient(transport=fake.transport) as http_client:
                client = sc.create_async_snowflake_client(
                    account="ab12345.ap-southeast-2",
                    user="tim",
                    private_key=rsa_private_key_pem,
                    role="NUI_ANALYTICS_API",
                    warehouse="ANALYTICS_WH",
                    database="NUI_MARKETS",
                    schema="ANALYTICS_API",
                    http_client=http_client,
                    log_queries=False,
                )
                rows = await client.query("SELECT id, payload FROM events WHERE kind = ?", ["news"])
                await client.aclose()
            return client, rows

        client, rows = asyncio.run(run_query())
        assert client.role == "NUI_ANALYTICS_API"
        assert client.warehouse == "ANALYTICS_WH"
        assert client.database == "NUI_MARKETS"
        assert client.schema == "ANALYTICS_API"
        assert rows == [{"id": 1, "payload": {"ok": True}}]


# ---------------------------------------------------------------------------
# Redaction: no key material in logs end-to-end
# ---------------------------------------------------------------------------


class TestRedactionEndToEnd:
    def test_no_key_material_in_logs_during_construction(
        self, clear_snowflake_env, caplog, mocker, rsa_private_key_pem
    ):
        passphrase = "TOP-SECRET-PASSPHRASE"
        # Encrypted key so both key bytes and passphrase are in play.
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        enc_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase.encode()),
        )
        mocker.patch(
            "nui_shared_utils.secrets_helper.get_secret",
            return_value={
                "account": "ab12345",
                "user": "svc",
                "private_key": enc_pem.decode("utf-8"),
                "private_key_passphrase": passphrase,
            },
        )
        with caplog.at_level(logging.DEBUG):
            client = sc.create_snowflake_client(secret_name="some-secret")
            client._notify("SELECT * FROM t WHERE x = ?", ["sensitive-bind"])
            client.close()
        assert passphrase not in caplog.text
        assert "BEGIN" not in caplog.text  # no PEM body
        assert "sensitive-bind" not in caplog.text  # no bind value


# ---------------------------------------------------------------------------
# Missing extra
# ---------------------------------------------------------------------------


class TestMissingExtra:
    def test_clear_error_when_unavailable(self, clear_snowflake_env, monkeypatch, rsa_private_key_pem):
        monkeypatch.setattr(sc, "SNOWFLAKE_SQL_API_AVAILABLE", False)
        with pytest.raises(ImportError) as exc:
            sc.create_snowflake_client(account="a", user="u", private_key=rsa_private_key_pem)
        assert "nui-python-shared-utils[snowflake]" in str(exc.value)

    def test_async_clear_error_when_unavailable(self, clear_snowflake_env, monkeypatch, rsa_private_key_pem):
        monkeypatch.setattr(sc, "SNOWFLAKE_SQL_API_AVAILABLE", False)
        with pytest.raises(ImportError) as exc:
            sc.create_async_snowflake_client(account="a", user="u", private_key=rsa_private_key_pem)
        assert "nui-python-shared-utils[snowflake]" in str(exc.value)


# ---------------------------------------------------------------------------
# Package wiring (top-level lazy export + back-compat shim)
# ---------------------------------------------------------------------------


class TestPackageWiring:
    def test_top_level_lazy_exports_resolve(self):
        """The PEP-562 lazy exports in __init__ resolve to the real callables."""
        import nui_shared_utils as nui

        assert nui.create_snowflake_client is sc.create_snowflake_client
        assert nui.create_async_snowflake_client is sc.create_async_snowflake_client
        assert nui.get_snowflake_credentials is sc.get_snowflake_credentials
        assert nui.redacting_query_logger is sc.redacting_query_logger

    def test_backwards_compat_shim_reexports(self):
        """The nui_lambda_shared_utils shim re-exports the adapter surface."""
        import warnings

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from nui_lambda_shared_utils import snowflake_client as shim

        assert shim.create_snowflake_client is sc.create_snowflake_client
        assert shim.get_snowflake_credentials is sc.get_snowflake_credentials
