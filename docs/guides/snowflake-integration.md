# Snowflake Integration

The Snowflake adapter wraps `snowflake-sql-api`, a pure-Python SQL API client.
Use it when a Lambda, CLI, or async API needs Snowflake reads or simple SQL
execution without bundling `snowflake-connector-python`.

Install the optional extra:

```bash
pip install "nui-python-shared-utils[snowflake]"
```

## Credential Resolution

Credentials resolve in the same order as the other shared clients:

1. explicit arguments
2. `SNOWFLAKE_*` environment variables
3. AWS Secrets Manager

Supported direct environment variables:

| Variable | Purpose |
| --- | --- |
| `SNOWFLAKE_ACCOUNT` | Snowflake account locator, for example `xy12345.ap-southeast-2` |
| `SNOWFLAKE_USER` | Service user |
| `SNOWFLAKE_PRIVATE_KEY` | Inline PEM private key |
| `SNOWFLAKE_PRIVATE_KEY_PATH` | Local PEM/DER private key path |
| `SNOWFLAKE_PRIVATE_KEY_PASSPHRASE` | Optional private key passphrase |
| `SNOWFLAKE_CREDENTIALS_SECRET` | Secret name override |

Secrets Manager values use this JSON shape:

```json
{
  "account": "xy12345.ap-southeast-2",
  "user": "SERVICE_USER",
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "private_key_passphrase": "optional"
}
```

Existing `snowflake-agent-credentials` secrets and service-specific secrets such
as a future `NUI_ANALYTICS_SVC` secret fit this shape. Pass `secret_name=` when a
service should not use the default or environment-selected secret.

## Sync Usage

```python
from nui_shared_utils import create_snowflake_client

with create_snowflake_client(
    secret_name="snowflake-agent-credentials",
    role="NUI_LAMBDA",
    warehouse="AGENT_WH",
    database="NUI_MARKETS",
    schema="ANALYTICS",
) as client:
    rows = client.query(
        "SELECT source_id, title FROM source_items WHERE source_id = ? LIMIT 10",
        ["edairynews"],
    )
```

The adapter applies NUI defaults for `role="NUI_LAMBDA"` and
`timezone="Pacific/Auckland"`. Override role, warehouse, database, schema, and
timezone explicitly for service accounts that need narrower production access.

## Async Usage

Use the async factory in FastAPI routes or other runtimes that already own an
event loop:

```python
from contextlib import asynccontextmanager
from fastapi import FastAPI
from nui_shared_utils import create_async_snowflake_client

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.snowflake = create_async_snowflake_client(
        secret_name="nui-analytics-snowflake",
        role="NUI_ANALYTICS_API",
        warehouse="ANALYTICS_WH",
        database="NUI_MARKETS",
        schema="ANALYTICS_API",
        statement_timeout=30,
    )
    try:
        yield
    finally:
        await app.state.snowflake.aclose()

app = FastAPI(lifespan=lifespan)
```

For Lambda handlers that use an async framework, create the client during
startup and close it during shutdown. For normal synchronous Lambda handlers,
prefer `create_snowflake_client`.

## Query Parameters

Snowflake SQL API bindings are positional `?` bindings:

```python
rows = client.query("SELECT id FROM trades WHERE solution_id = ?", [solution_id])
```

Do not use connector-style `%s` placeholders or named `:name` bindings with this
adapter.

## Logging And Metrics Hooks

By default the adapter installs a redacting query logger. It logs SQL text and
bind parameter count, never bind values:

```python
client = create_snowflake_client(log_sql_max_chars=500)
```

For service metrics, pass a custom `on_query` hook:

```python
def record_query(sql, params):
    metrics.put_metric("SnowflakeQuery", 1, "Count")

client = create_snowflake_client(on_query=record_query)
```

Keep hooks generic. Domain-specific table names, market-intelligence state
transitions, and analytics endpoint logic belong in the consuming service.

## Offline Tests

Use `snowflake_sql_api.testing.FakeSnowflake` to test service code without a
network or real Snowflake account:

```python
import httpx
from snowflake_sql_api.testing import FakeSnowflake
from nui_shared_utils import create_async_snowflake_client

async def test_query(rsa_private_key_pem):
    fake = FakeSnowflake()
    fake.register("SELECT 1 AS value", [{"value": 1}])

    async with httpx.AsyncClient(transport=fake.transport) as http_client:
        client = create_async_snowflake_client(
            account="xy12345.ap-southeast-2",
            user="TEST_USER",
            private_key=rsa_private_key_pem,
            http_client=http_client,
            log_queries=False,
        )
        assert await client.query_scalar("SELECT 1 AS value") == 1
```

Add live smoke tests for behavior that FakeSnowflake cannot prove, such as
`MERGE` row counts, `PARSE_JSON(?)`, and timestamp/session timezone semantics.
