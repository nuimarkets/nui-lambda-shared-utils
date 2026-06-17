"""NUI adapter for the ``snowflake-sql-api`` pure-Python Snowflake client.

This is the NUI-opinionated layer over the generic
`snowflake-sql-api <https://github.com/hampsterx/snowflake-sql-api>`_ package.
The generic package stays vendor-neutral (no account/role/timezone defaults);
all NUI specifics live here:

- **Keypair from Secrets Manager.** Credentials (account, user, PEM private key,
  optional passphrase) are loaded from AWS Secrets Manager by default, with
  environment-variable and explicit-argument overrides.
- **NUI session defaults.** ``TIMEZONE='Pacific/Auckland'`` and role
  ``NUI_LAMBDA`` are applied unless overridden. (``WEEK_START`` is *not* set: the
  SQL API only accepts an allow-list of session parameters in a request and
  rejects ``WEEK_START`` with HTTP 400. The API is stateless per statement, so
  ``ALTER SESSION`` cannot substitute. Set it on the Snowflake user/role default
  if a consumer needs Monday-first weeks.)
- **Redacted query logging.** A logging hook records the statement text
  (truncated) and the *number* of bind parameters, never the bind values, JWTs,
  key material, or secret names.
- **Sync by default.** :func:`create_snowflake_client` returns the synchronous
  client; use :func:`create_async_snowflake_client` only for a Lambda already
  running on an event loop.

Install the extra to pull the client in::

    pip install 'nui-python-shared-utils[snowflake]'

Using any factory here without that extra raises a clear :class:`ImportError`
rather than failing at package import time.
"""

import logging
import os
from typing import Any, Callable, Dict, Optional, Sequence, Union

log = logging.getLogger(__name__)

# Type alias for the on_query callback: receives SQL text and optional bind params.
QueryHook = Callable[[str, Optional[Sequence[Any]]], None]

# Optional dependency: the generic snowflake-sql-api client. Guarded so the
# package imports without the [snowflake] extra; factories raise a clear error.
try:
    from snowflake_sql_api import AsyncSnowflakeClient, SnowflakeClient

    SNOWFLAKE_SQL_API_AVAILABLE = True
except ModuleNotFoundError as exc:  # pragma: no cover - flag is patched in tests
    # Only the missing extra itself flips the availability flag. If the package
    # is installed but a *dependency of it* is missing, re-raise so the user sees
    # the real traceback instead of a misleading "not installed" message.
    if exc.name and exc.name.split(".")[0] != "snowflake_sql_api":
        raise
    AsyncSnowflakeClient = None  # type: ignore[assignment,misc]
    SnowflakeClient = None  # type: ignore[assignment,misc]
    SNOWFLAKE_SQL_API_AVAILABLE = False

__all__ = [
    "DEFAULT_TIMEZONE",
    "DEFAULT_ROLE",
    "DEFAULT_SECRET_NAME",
    "get_snowflake_credentials",
    "create_snowflake_client",
    "create_async_snowflake_client",
    "redacting_query_logger",
]

#: NUI session defaults. Every one of these is overridable per call.
DEFAULT_TIMEZONE = "Pacific/Auckland"
DEFAULT_ROLE = "NUI_LAMBDA"

#: Secrets Manager secret name used when none is supplied via argument or the
#: ``SNOWFLAKE_CREDENTIALS_SECRET`` environment variable.
DEFAULT_SECRET_NAME = "snowflake-credentials"

#: Default ``User-Agent`` sent by NUI clients (overridable via ``user_agent``).
_USER_AGENT = "nui-python-shared-utils-snowflake"

# Secret/credential field aliases. The secret JSON may use any of these.
_ACCOUNT_FIELDS = ("account", "snowflake_account")
_USER_FIELDS = ("user", "username", "snowflake_user")
_PRIVATE_KEY_FIELDS = ("private_key", "privateKey", "snowflake_private_key")
_PASSPHRASE_FIELDS = (
    "private_key_passphrase",
    "passphrase",
    "private_key_password",
)


def _require_snowflake_sql_api() -> None:
    """Raise a clear, actionable error when the optional extra is missing."""
    if not SNOWFLAKE_SQL_API_AVAILABLE:
        raise ImportError(
            "snowflake-sql-api is not installed. Install it with: pip install 'nui-python-shared-utils[snowflake]'"
        )


def _first(mapping: Dict[str, Any], keys: Sequence[str]) -> Optional[Any]:
    """Return the first present, non-empty value among ``keys`` in ``mapping``."""
    for key in keys:
        value = mapping.get(key)
        if value:
            return value
    return None


def _as_key_bytes(value: Any) -> bytes:
    """Coerce a PEM private key (``str`` or ``bytes``) to ``bytes``."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    raise ValueError("private_key must be PEM text (str) or bytes")


def _resolve_secret_name(secret_name: Optional[str]) -> str:
    """Resolve the secret name: explicit arg > env var > default."""
    return secret_name or os.environ.get("SNOWFLAKE_CREDENTIALS_SECRET") or DEFAULT_SECRET_NAME


def _env_private_key() -> Optional[bytes]:
    """Read key bytes from ``SNOWFLAKE_PRIVATE_KEY`` (inline PEM) or ``SNOWFLAKE_PRIVATE_KEY_PATH`` (file)."""
    key_pem = os.environ.get("SNOWFLAKE_PRIVATE_KEY")
    if key_pem:
        return _as_key_bytes(key_pem)
    key_path = os.environ.get("SNOWFLAKE_PRIVATE_KEY_PATH")
    if key_path:
        with open(key_path, "rb") as handle:
            return handle.read()
    return None


def get_snowflake_credentials(
    secret_name: Optional[str] = None,
    *,
    account: Optional[str] = None,
    user: Optional[str] = None,
    private_key: Optional[Union[bytes, str]] = None,
    private_key_passphrase: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve Snowflake keypair credentials.

    Each field is resolved independently with strict **explicit arg > env var >
    Secrets Manager** precedence, so an explicit value is never shadowed by a
    lower tier:

    - ``account`` / ``user``: explicit arg, else ``SNOWFLAKE_ACCOUNT`` /
      ``SNOWFLAKE_USER``, else the secret's ``account`` / ``user`` field.
    - ``private_key``: explicit arg (bytes/PEM str), else ``SNOWFLAKE_PRIVATE_KEY``
      (inline PEM) / ``SNOWFLAKE_PRIVATE_KEY_PATH`` (file), else the secret's
      ``private_key`` field (PEM text).
    - ``private_key_passphrase`` is paired with the key's source: an explicit
      passphrase arg always wins, otherwise the passphrase comes from the **same
      tier the key came from** (env key -> ``SNOWFLAKE_PRIVATE_KEY_PASSPHRASE``;
      secret key -> the secret's passphrase field). An explicit key is therefore
      never silently paired with a stale env/secret passphrase.

    Secrets Manager is only contacted when ``account``, ``user`` or the key is
    still unresolved after the explicit/env tiers.

    Returns a dict with ``account``, ``user``, ``private_key`` (bytes) and
    ``private_key_passphrase`` keys.
    """
    resolved_account = account or os.environ.get("SNOWFLAKE_ACCOUNT")
    resolved_user = user or os.environ.get("SNOWFLAKE_USER")

    # Resolve key + passphrase together so they always come from one source.
    if private_key is not None:
        resolved_key: Optional[bytes] = _as_key_bytes(private_key)
        resolved_passphrase = private_key_passphrase  # explicit arg only
    else:
        env_key = _env_private_key()
        if env_key is not None:
            resolved_key = env_key
            resolved_passphrase = (
                private_key_passphrase
                if private_key_passphrase is not None
                else os.environ.get("SNOWFLAKE_PRIVATE_KEY_PASSPHRASE")
            )
        else:
            resolved_key = None
            resolved_passphrase = private_key_passphrase  # may be filled from secret

    # Contact Secrets Manager only for what is still missing.
    if not (resolved_account and resolved_user and resolved_key is not None):
        from .secrets_helper import get_secret

        resolved_name = _resolve_secret_name(secret_name)
        secret = get_secret(resolved_name)

        resolved_account = resolved_account or _first(secret, _ACCOUNT_FIELDS)
        resolved_user = resolved_user or _first(secret, _USER_FIELDS)
        if resolved_key is None:
            secret_key = _first(secret, _PRIVATE_KEY_FIELDS)
            resolved_key = _as_key_bytes(secret_key) if secret_key else None
            if resolved_passphrase is None:
                resolved_passphrase = _first(secret, _PASSPHRASE_FIELDS)

        missing = [
            name
            for name, value in (
                ("account", resolved_account),
                ("user", resolved_user),
                ("private_key", resolved_key),
            )
            if not value
        ]
        if missing:
            # Name the secret but never its contents.
            raise ValueError(f"Snowflake secret '{resolved_name}' is missing required field(s): " + ", ".join(missing))

    if not resolved_key:
        # An explicit empty key (``b""``) or an empty key file would otherwise
        # slip past the missing-field check above (which only runs in the secret
        # branch). Fail clearly here regardless of the key's source.
        raise ValueError("a non-empty private_key is required")

    return {
        "account": resolved_account,
        "user": resolved_user,
        "private_key": resolved_key,
        "private_key_passphrase": resolved_passphrase,
    }


def redacting_query_logger(
    logger: Optional[logging.Logger] = None,
    *,
    level: int = logging.DEBUG,
    max_sql_chars: int = 1000,
) -> QueryHook:
    """Build an ``on_query`` hook that logs statements without leaking values.

    The returned callback logs the (truncated) SQL text and the *count* of bind
    parameters. It never logs the bind values themselves, so user data, secrets,
    and PII passed as parameters stay out of the logs.

    Args:
        logger: Destination logger. Defaults to this module's logger.
        level: Log level for the query record (default ``DEBUG``).
        max_sql_chars: Truncate the logged SQL beyond this many characters.
    """
    target = logger or log

    def _hook(sql: str, params: Optional[Sequence[Any]]) -> None:
        truncated = sql if len(sql) <= max_sql_chars else sql[:max_sql_chars] + "...(truncated)"
        param_count = len(params) if params else 0
        target.log(
            level,
            "snowflake query",
            extra={"sql": truncated, "bind_param_count": param_count},
        )

    return _hook


def _resolve_on_query(
    on_query: Optional[QueryHook],
    logger: Optional[logging.Logger],
    log_queries: bool,
    log_sql_max_chars: int,
) -> Optional[QueryHook]:
    """Pick the query hook: explicit override, redacting logger, or none."""
    if on_query is not None:
        return on_query
    if log_queries:
        return redacting_query_logger(logger, max_sql_chars=log_sql_max_chars)
    return None


def _client_kwargs(
    creds: Dict[str, Any],
    *,
    role: Optional[str],
    warehouse: Optional[str],
    database: Optional[str],
    schema: Optional[str],
    timezone: Optional[str],
    parameters: Optional[Dict[str, Any]],
    on_query: Optional[QueryHook],
    user_agent: Optional[str],
    extra: Dict[str, Any],
) -> Dict[str, Any]:
    """Shared keyword assembly for both sync and async client construction.

    ``TIMEZONE`` rides the client's ``timezone`` argument; any caller-supplied
    ``parameters`` pass straight through to the SQL API ``parameters`` map. Note
    the SQL API only accepts an allow-list of session parameters there (TIMEZONE
    and output-format params are fine; WEEK_START is rejected, see module docs).
    """
    # Start from passthrough kwargs, then let adapter-managed keys win, so an
    # unexpected ``extra`` key can never silently override a managed one (the
    # factories' named params already capture managed keys, so a caller cannot
    # reach these via ``**client_kwargs`` today; this guards a future key add).
    kwargs: Dict[str, Any] = dict(extra)
    kwargs.update(
        {
            "account": creds["account"],
            "user": creds["user"],
            "private_key": creds["private_key"],
            "private_key_passphrase": creds.get("private_key_passphrase"),
            "role": role,
            "warehouse": warehouse,
            "database": database,
            "schema": schema,
            "timezone": timezone,
            "parameters": dict(parameters) if parameters else None,
            "on_query": on_query,
            "user_agent": user_agent or _USER_AGENT,
        }
    )
    return kwargs


def create_snowflake_client(
    *,
    secret_name: Optional[str] = None,
    account: Optional[str] = None,
    user: Optional[str] = None,
    private_key: Optional[Union[bytes, str]] = None,
    private_key_passphrase: Optional[str] = None,
    role: Optional[str] = DEFAULT_ROLE,
    warehouse: Optional[str] = None,
    database: Optional[str] = None,
    schema: Optional[str] = None,
    timezone: Optional[str] = DEFAULT_TIMEZONE,
    parameters: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None,
    log_queries: bool = True,
    log_sql_max_chars: int = 1000,
    on_query: Optional[QueryHook] = None,
    user_agent: Optional[str] = None,
    **client_kwargs: Any,
) -> "SnowflakeClient":
    """Construct a synchronous Snowflake client with NUI defaults.

    This is the adapter's default entry point. Credentials are resolved via
    :func:`get_snowflake_credentials`; NUI session defaults (timezone, role) are
    applied unless overridden; a redacting query-logging hook is wired in unless
    ``log_queries=False`` or a custom ``on_query`` is given.

    Extra keyword arguments (``timeout``, ``statement_timeout``,
    ``poll_interval``, ``retry_policy``, ``host`` ...) pass straight through to
    :class:`snowflake_sql_api.SnowflakeClient`.

    Returns:
        A ready-to-use :class:`snowflake_sql_api.SnowflakeClient`.
    """
    _require_snowflake_sql_api()
    creds = get_snowflake_credentials(
        secret_name,
        account=account,
        user=user,
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
    )
    hook = _resolve_on_query(on_query, logger, log_queries, log_sql_max_chars)
    kwargs = _client_kwargs(
        creds,
        role=role,
        warehouse=warehouse,
        database=database,
        schema=schema,
        timezone=timezone,
        parameters=parameters,
        on_query=hook,
        user_agent=user_agent,
        extra=client_kwargs,
    )
    return SnowflakeClient(**kwargs)


def create_async_snowflake_client(
    *,
    secret_name: Optional[str] = None,
    account: Optional[str] = None,
    user: Optional[str] = None,
    private_key: Optional[Union[bytes, str]] = None,
    private_key_passphrase: Optional[str] = None,
    role: Optional[str] = DEFAULT_ROLE,
    warehouse: Optional[str] = None,
    database: Optional[str] = None,
    schema: Optional[str] = None,
    timezone: Optional[str] = DEFAULT_TIMEZONE,
    parameters: Optional[Dict[str, Any]] = None,
    logger: Optional[logging.Logger] = None,
    log_queries: bool = True,
    log_sql_max_chars: int = 1000,
    on_query: Optional[QueryHook] = None,
    user_agent: Optional[str] = None,
    **client_kwargs: Any,
) -> "AsyncSnowflakeClient":
    """Construct an asynchronous Snowflake client with NUI defaults.

    Async parity with :func:`create_snowflake_client`. Use only inside a Lambda
    already running on an event loop; the sync client is the NUI default
    otherwise.

    Returns:
        A ready-to-use :class:`snowflake_sql_api.AsyncSnowflakeClient`.
    """
    _require_snowflake_sql_api()
    creds = get_snowflake_credentials(
        secret_name,
        account=account,
        user=user,
        private_key=private_key,
        private_key_passphrase=private_key_passphrase,
    )
    hook = _resolve_on_query(on_query, logger, log_queries, log_sql_max_chars)
    kwargs = _client_kwargs(
        creds,
        role=role,
        warehouse=warehouse,
        database=database,
        schema=schema,
        timezone=timezone,
        parameters=parameters,
        on_query=hook,
        user_agent=user_agent,
        extra=client_kwargs,
    )
    return AsyncSnowflakeClient(**kwargs)
