# Structured Logging Contract

A canonical, dotted, snake_case field vocabulary for structured logs, plus
backend-agnostic binding helpers that emit it. One contract so logs from
short-lived Lambda functions and long-running services share the same field shape.

- **What it is**: an importable field registry (`FIELDS` / `F`), request-scoped
  binders for the two logging backends in use, a payload redactor, and derivations
  for the redaction set and the field-migration map.
- **Store-neutral**: it governs how services *emit* fields, not how any log store
  indexes them. A consistent, typed vocabulary matters under any backend: a
  schema-enforcing store (Elasticsearch) turns field drift into loud errors; a
  schema-less store (VictoriaLogs, Loki) accepts drift silently and lets queries
  and alerts skew. This registry is the producer-side discipline that prevents both.
- **Why dotted**: dotted keys survive Powertools `append_keys` incremental binding
  where nested dicts clobber (a producer-side property, independent of the store).
  See [ADR-001](../decisions/ADR-001-structured-logging-field-vocabulary.md).
- **Zero heavy deps**: the whole contract is standard-library only. Importing it
  pulls in no boto3, elasticsearch, slack, or powertools.

## Table of Contents

- [Quick Start](#quick-start)
- [The Field Registry](#the-field-registry)
- [Binding Helpers](#binding-helpers)
- [Request Scope and Context Leakage](#request-scope-and-context-leakage)
- [Redaction](#redaction)
- [Extending With Domain Fields](#extending-with-domain-fields)
- [Deriving the Redaction Set and Migration Map](#deriving-the-redaction-set-and-migration-map)
- [Choosing a Backend](#choosing-a-backend)

## Quick Start

```python
import logging
from nui_shared_utils import F, stdlib_binder, bind_request, bind_user

logger = logging.getLogger("my-service")
binder = stdlib_binder(logger)  # or powertools_binder(powertools_logger)

def handle(request):
    with binder.request_scope():                       # context cleared on exit
        bind_request(binder, method=request.method, path=request.path,
                     request_id=request.id)
        bind_user(binder, id=request.user.id, email=request.user.email,
                  org_id=request.user.org_id)

        # Every log inside the scope carries the bound dotted keys.
        logger.info("handling request")
        ...
        logger.info("response", extra={F.RESPONSE_STATUS: 200,
                                       F.RESPONSE_DURATION_MS: elapsed_ms})
```

Emitted (dotted keys, queryable as `request.method`, `user.org_id`, ...):

```json
{"message": "response", "request.method": "POST", "request.path": "/orders",
 "request.id": "abc", "user.id": "u1", "user.email": "a@b.com",
 "user.org_id": "org9", "response.status": 200, "response.duration_ms": 42}
```

## The Field Registry

Every canonical field is declared once in `nui_shared_utils.logging.fields`. Use the
`F` constants at call sites so you never hand-type a dotted string:

```python
from nui_shared_utils import F

logger.info("done", extra={F.RESPONSE_STATUS: 200, F.TARGET: "responses"})
```

Core namespaces:

| Namespace | Fields | Notes |
|-----------|--------|-------|
| `request.*` | `id`, `method`, `path`, `ip`, `body_json` | `body_json` is opaque, retrieval-only (not indexed) |
| `user.*` | `id`, `email`, `org_id`, `roles` | the principal; `org_id` is the tenant (`company.*` folds in here) |
| `response.*` | `status`, `duration_ms`, `output_json` | `output_json` is opaque, retrieval-only |
| `route.*` | `name`, `path` | matched route |
| `error.*` | `type`, `message`, `stack` | set by `log_exception` |
| `trace.*` | `id`, `span_id` | Powertools / X-Ray correlation |
| `git.*` | `commit`, `branch`, `tag` | optional build context, consumer-bound |
| `target` | (single field) | log index / stream routing |

Each field carries type, indexed flag, sensitivity, and deprecated aliases. `user.email`
is `pii`; `request.body_json` / `response.output_json` are `redact`. Deprecated names
map forward, e.g. `request.user` → `user.email`, `api.duration_ms` → `response.duration_ms`.

## Binding Helpers

Helpers take keyword args and emit the right dotted keys. `None` values are dropped,
so you can pass everything you have and unset fields simply do not appear.

```python
from nui_shared_utils import (
    bind_request, bind_user, bind_build_context, log_exception,
    request_body_fields, response_output_fields,
)

bind_request(binder, method="POST", path="/orders", ip=client_ip, request_id=rid)
bind_user(binder, id=u.id, email=u.email, org_id=u.org_id, roles=u.roles)
bind_build_context(binder, commit=GIT_SHA, branch=GIT_BRANCH)   # optional, at startup

# Exceptions: error.stack is set EXPLICITLY (relying on the backend's own
# exc_info emits its field name, e.g. Powertools' `stack_trace`, not error.stack).
try:
    do_work()
except Exception as exc:
    log_exception(binder, exc, "work failed")   # error.type / error.message / error.stack

# Opaque payloads: redacted, then serialised to ONE string field so unbounded
# caller-controlled keys cannot explode the index field count.
logger.info("request body", extra=request_body_fields(request.json))
logger.info("upstream response", extra=response_output_fields(upstream.body))
```

## Request Scope and Context Leakage

Bound context is **request-scoped**. `binder.request_scope()` sets a `contextvars`
token on entry and unbinds on exit. This matters on both backends:

- **Long-running services** (ECS): without a scope, a bound `user.id` would persist
  and bleed into the next, concurrent request. The stdlib binder stores context in a
  `contextvars.ContextVar`, so concurrent requests (each its own task / thread) are
  isolated and async-safe.
- **Warm Lambda invocations**: without a scope, keys bound in one invocation would be
  inherited by the next on the same warm container. The Powertools binder tracks keys
  bound inside the scope and calls `remove_keys` on exit.

Wire `request_scope()` into the request-end tween (services) or the handler `finally`
(Lambda). Always bind inside the scope.

```python
with binder.request_scope():
    bind_user(binder, id=u.id)
    ...
# here: nothing bound; the next request starts clean
```

### stdlib binder: child loggers and handler timing

`stdlib_binder(logger)` attaches its context filter to `logger` and to the effective
handlers up the hierarchy. This covers the common layout where the binder is built on
an app / root logger that owns the JSON handler, but records are emitted via child
loggers (`logging.getLogger(__name__)`): a parent logger's *filters* do not run for a
child's records, but its *handlers* do, so context is injected at the handler.

If you add the JSON handler *after* constructing the binder, or the handler lives on a
logger other than the one you passed, attach the filter explicitly:

```python
binder = stdlib_binder(logging.getLogger("my-service"))
handler = make_json_handler()           # configured later
logging.getLogger().addHandler(handler)
binder.install_on(handler)              # or install_on(a_logger)
```

The filter is a no-op outside a `request_scope` (empty context), so attaching it to a
shared or root handler is safe.

## Redaction

`request_body_fields` / `response_output_fields` run the payload through
`default_redactor` before serialising. Two strategies:

- **Deny-list (default)**: masks keys whose name matches a base pattern set
  (`password`, `token`, `secret`, `authorization`, `api_key`, `cookie`, ...) or a
  registry-derived sensitive leaf (`email`). Matching is by whole snake_case word, so
  `X-Api-Key` and `accessToken` are caught but `wildcard` / `author` are not. Good for
  general debug payloads where most keys are legitimate.
- **Allow-list (`allow_only=[...]`)**: keeps only the named keys, masks everything
  else. Use on PII-heavy routes (auth, profile, anything logging headers). The
  deny-list still applies as a backstop.

```python
# deny-list default
request_body_fields(payload)
# allow-list for a PII-heavy route
request_body_fields(profile_payload, allow_only=["display_name", "locale"])
# extend the deny-list for this call
request_body_fields(payload, deny_extra=["internal_ref"])
```

Identity fields you *want* logged (email, user id) belong in `bind_user`, which does
not pass through the redactor. Do not rely on the body redactor to surface identity.

Known v1 gaps (tracked for v2): value-embedded secrets (a token inside a URL string)
and objects whose `__str__` leaks are not caught, only key *names* are matched.

## Extending With Domain Fields

The shared package stays generic: domain fields (`order.*`, `tender.*`, `auth.*`, ...)
live in the consumer, not here. Declare them as constants and drift-check them in CI:

```python
# in your service
class OrderFields:
    ORDER_ID = "order.id"
    ORDER_STATE = "order.state"

logger.info("order processed", extra={OrderFields.ORDER_ID: oid})   # emitted as order.id (order.* namespace)
```

```python
# in your service's tests
from nui_shared_utils import validate_fields
from myservice.log_fields import OrderFields

def test_order_fields_follow_convention():
    assert validate_fields(OrderFields) == []   # dotted + snake_case
```

## Deriving the Redaction Set and Migration Map

The registry is the single source of truth for two otherwise-separate lists:

```python
from nui_shared_utils import redaction_keys, alias_map

redaction_keys()  # -> frozenset of sensitive leaf names for the deny set
alias_map()       # -> {"request.user": "user.email", "api.duration_ms": "response.duration_ms", ...}
```

`redaction_keys()` extends the redactor's deny set with the registry's `pii` / `redact`
leaves. `alias_map()` drives an old-name → canonical migration or dual-read.

A schema-enforcing store (e.g. Elasticsearch) can also derive its index mapping from
the registry's `type` / `indexed` metadata (define once, derive the mapping). That
export is store-specific and lives with the store's own tooling, not in this
store-neutral core.

## Choosing a Backend

Pick the binder once, at construction (not by duck-typing, which breaks on
`LoggerAdapter`):

| Backend | Builder | When |
|---------|---------|------|
| AWS Powertools `Logger` | `powertools_binder(logger)` | Lambda functions using Powertools |
| stdlib `logging.Logger` | `stdlib_binder(logger)` | services on the JSON-formatter / `pythonjsonlogger` path |

Both expose the same surface (`bind`, `unbind`, `request_scope`) and the same
`bind_request` / `bind_user` / ... helpers work against either.

## Related Documentation

- [ADR-001: Structured logging field vocabulary](../decisions/ADR-001-structured-logging-field-vocabulary.md) - the rationale
- [AWS Powertools Integration](powertools-integration.md) - the logger factory the Powertools binder wraps
- [Log Processing](log-processing.md) - Kinesis extraction and ES index naming
