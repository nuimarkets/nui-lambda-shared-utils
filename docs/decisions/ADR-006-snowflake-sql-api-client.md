# ADR-006: Snowflake access via the pure-Python SQL API client

**Status**: Proposed
**Date**: 2026-07-13

## Context

This package is a shared utility layer for AWS Lambda functions, CLIs, and async API
services. Bundle size and pure-Python portability are first-order constraints: every
integration ships as an optional extra so a consumer pulls only the dependency it uses,
and the package avoids native/C-extension builds so one wheel runs unchanged across
Lambda runtimes, layers, and local tooling with no compile step.

Snowflake access comes in two dependency shapes. The official
`snowflake-connector-python` is a large connector with native (C-extension) components:
Arrow result decoding, pyarrow/cython wheels, a binary footprint that dominates a Lambda
bundle and pins the build to a specific platform/Python ABI. The Snowflake **SQL REST
API** needs none of that. It is authenticated HTTP (keypair-minted JWT bearer tokens,
positional `?` bindings, JSON result sets), fully expressible in pure Python.

The consumers here (analytics reads and simple SQL execution from Lambdas and a FastAPI
service) need the query surface the SQL API already covers, not the connector's native
result-streaming or stateful-session features.

## Decision

Snowflake access is provided by wrapping the pure-Python `snowflake-sql-api` package
(the Snowflake SQL REST API) with a thin NUI adapter, exposed through the optional
`snowflake` extra (`snowflake-sql-api>=0.1.1,<0.2.0`). The generic package stays
vendor-neutral; all NUI opinion lives in the adapter
(`nui_shared_utils/snowflake_client.py`):

- **Sync and async client factories.** `create_snowflake_client` (the default) and
  `create_async_snowflake_client` (for a Lambda or FastAPI app already on an event loop)
  return ready `SnowflakeClient` / `AsyncSnowflakeClient` instances. Both run through one
  shared keyword-assembly path, so sync and async stay at feature parity.
- **Keypair authentication.** Credentials (account, user, PEM private key, optional
  passphrase) resolve per field with strict `explicit-arg > SNOWFLAKE_* env > AWS Secrets
  Manager` precedence; the underlying SQL API client mints short-lived JWT bearer tokens
  from the keypair. Secrets Manager is contacted only for fields still unresolved after
  the explicit/env tiers. This per-field resolution is a deliberate divergence from
  ADR-004's whole-dict ladder (where an explicit `credentials` dict is used as-is and nothing
  else is consulted): a keypair's fields legitimately come from different sources (account and
  user from env, private key from Secrets Manager), so each resolves independently. A field left
  unset at every tier surfaces as a missing-credential error at client construction, not a silent
  partial.
- **Redacted query logging.** A default `redacting_query_logger` hook records the
  (truncated) statement text and the *count* of bind parameters, never the bind values,
  JWTs, key material, or secret names. Callers can pass a custom `on_query` hook (for
  metrics, for example) or disable logging.
- **Overridable session defaults.** `TIMEZONE='Pacific/Auckland'` and role `NUI_LAMBDA`
  apply unless overridden. These are baked geography/org defaults, the class ADR-002 (and the
  `AGENTS.md` DON'T list) caution against, and are kept here as a deliberate, bounded exception:
  both are documented and overridable per call, so a consumer in another region or account
  supplies its own at the factory call rather than inheriting a value that silently encodes
  one geography.

Import is guarded: using a factory without the extra raises a clear `ImportError` rather
than failing at package import. Introduced in commit `d0af0b6` (PR #25).

## Alternatives considered

- **Bundle `snowflake-connector-python`.** The official, fullest-featured client: native
  Arrow result streaming, richer session/cursor semantics, `%s` and named bindings.
  Rejected as the dependency here because its native wheels and binary footprint fight
  both package constraints at once, bundle size (it dominates a Lambda artifact) and
  pure-Python portability (the C-extension build pins platform/ABI and needs a compile
  step). Its extra surface is not what these consumers need.
- **Vendor the SQL API calls directly** (hand-rolled HTTP client plus JWT minting inside
  this package). Rejected: the generic `snowflake-sql-api` package already owns that
  surface plus an offline test transport (`FakeSnowflake`); duplicating it here couples
  the shared utils to Snowflake's REST contract for no gain.
- **Ship no Snowflake helper and let each consumer wire its own.** Rejected: credential
  resolution, redaction, and session defaults are exactly the cross-consumer patterns a
  shared layer exists to standardize; re-implementing them per service re-introduces
  drift and redaction gaps.

## Consequences

- The Snowflake path stays pure-Python and small: the `snowflake` extra adds an HTTP
  client, not a native connector, so it fits Lambda bundles and runs unchanged across
  runtimes.
- The adapter's reach is bounded by the SQL REST API surface. A concrete limit already
  lives with this: the SQL API accepts only an allow-list of session parameters per
  request and rejects `WEEK_START` with HTTP 400, and being stateless per statement it
  offers no `ALTER SESSION` escape hatch, so Monday-first weeks must be set on the
  Snowflake user/role default instead. Capabilities outside the REST surface (native
  result streaming, stateful session mutation) are unavailable by construction.
- One credential/redaction/session-default contract across sync and async consumers;
  bind values and key material stay out of logs by default.

## Load-bearing premises (supersede triggers)

- **The SQL REST API covers the query surface these consumers need.** If a required
  capability were SQL-API-unavailable (native result streaming, a stateful session
  feature the REST contract cannot express), the native connector reopens as the
  dependency for that need.
- **Pure-Python / small-bundle portability outweighs the native connector's extra
  features.** If this package stopped targeting size-constrained, compile-free runtimes,
  the bundle-size/portability tradeoff that rejects `snowflake-connector-python` no
  longer holds and that choice returns to the table.
- **The generic `snowflake-sql-api` package remains the SQL API surface.** The adapter is
  a thin layer over it; if that package stopped tracking the REST contract or dropped its
  offline test transport, vendoring the calls (or adopting another SQL-API client)
  returns as an option.
