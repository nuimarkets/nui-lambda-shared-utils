# ADR-001: Structured logging field vocabulary

**Status**: Proposed
**Date**: 2026-07-11

## Context

This package is the shared logging entry point for a fleet of Python Lambda functions and
long-running services whose structured logs are shipped to a central log store and queried by
operators and automated agents. Reliable querying, dashboards, and alerting need a predictable
field shape: consistent key names and stable leaf types across every producer.

Today the logger helper (`get_powertools_logger`) sets service, level, timezone, and timestamp
format, but takes no position on field names or shape. Each call site hand-assembles its own
`extra={}` keys. Across the fleet this has grown several incompatible conventions in the same log
stream: flat single-word keys (`order_id`), dotted namespaced keys (`request.order_id`), nested
dicts (`extra={"request": {...}}`), and unstructured message strings.

This is a **producer-side** problem, and its cost is independent of which store the logs land in:

- A **schema-enforcing** store (Elasticsearch) turns field drift into loud failures: mapping
  conflicts and silent nulls when `status` is a number in one document and a string in the next.
- A **schema-less** store (VictoriaLogs, Loki) accepts the drift silently. `{"status": 200}` and
  `{"status": "timeout"}` are both ingested with no error, and the skew surfaces later as a
  dashboard panel or an alert rule (`5xx rate`, `exception spike`) that quietly stops matching.

So the log store is deliberately out of scope for this decision (it is itself under evaluation),
and the contract is **store-neutral**. The one property of the stack that does constrain the wire
shape is producer-side:

**The Powertools `Logger.append_keys` merge is shallow.** Binding context incrementally with
nested dicts clobbers earlier keys: `append_keys(request={"a": 1})` then `append_keys(request={"b": 2})`
emits `request={"b": 2}` and loses `a`. Dotted keys (`append_keys(**{"request.a": 1})`, then
`request.b`) are independent top-level keys and both survive. (Confirmed on `aws-lambda-powertools`
3.6.0.) Incremental binding (bind request at entry, add more later) therefore requires dotted keys.

(Incidental, not load-bearing: while Elasticsearch is a store, it expands dotted field names into
`object`-datatype paths at index time, so `request.order_id` and `{"request": {"order_id": ...}}`
map and query identically. Wire shape does not change queryability there. A store swap does not
disturb this decision because the decision does not rest on it.)

## Decision

This package owns a canonical **dotted** field vocabulary as the fleet's logging contract, defined
independently of any log store:

- **A field registry (schema object)**: one importable module where each canonical dotted field
  carries its type, whether it is indexed (i.e. meant to be queried vs retrieval-only), a
  sensitivity flag, and any deprecated aliases. Covers `request.*`, `user.*`, `route.*`,
  `response.*`, `error.*`, `trace.*`, `request.body_json` / `response.output_json`, plus a `target`
  routing field. Single source of truth from which the default redaction set and the field-migration
  map are derived. (A plain `dataclass`, not a heavyweight model dependency: the registry is static
  metadata.)
- **Binding helpers** (`bind_request`, `bind_user`, `log_exception`, and a body helper that
  serialises to a single `request.body_json` string with redaction) so callers never hand-type keys.
- **A consistency test** that asserts the registry's names, importable so consumers guard against
  drift in CI.
- The vocabulary is **backend-agnostic**: consumed identically from the Powertools path and from a
  standard-library JSON-formatter path, so short-lived functions and long-running services share one
  contract.

Wire shape is **dotted**, names are **snake_case** dotted paths. Nested-dict emission is not used.

## Alternatives considered

- **Nested dicts as the emitted shape.** Ergonomic to build in one call and natural in Python.
  Rejected because it clobbers under incremental `append_keys` binding, and because the fleet's
  existing namespaced emitters already use dotted. Nested-*feeling* ergonomics are kept: the binding
  helpers take keyword args and emit dotted keys.
- **Flat single-word keys** (`order_id`, `user_id`). Simplest, but no namespacing, so unrelated
  fields collide and there is no structural grouping for operators or mappings.
- **A per-repo constants module.** Two codebases independently grew partial dotted taxonomies, which
  proves the convention is wanted, but a per-repo copy re-introduces drift. One shared registry is
  the point.
- **Bake the vocabulary into a single logger factory.** Cannot span the two logging backends in use,
  so the contract lives in a backend-agnostic registry plus helpers rather than a factory.
- **Defer the contract until the log store is chosen.** Rejected: the drift is producer-side and
  costs the same under either candidate store. A store-neutral contract is the piece that survives
  (and is required by) a store migration, not one that blocks on it. Under a schema-less store it is
  the *only* drift guard, since nothing downstream rejects a malformed field.

## Consequences

- One field shape across the fleet; the cost of field-name/type drift (loud mapping conflicts on a
  schema-enforcing store, silent query/alert skew on a schema-less one) goes away as consumers adopt
  it.
- `request.body_json` as one opaque, retrieval-only string keeps unbounded, caller-controlled payloads
  from bloating the field set (a concern under any store, acute on a mapping-based one), and
  centralises redaction in one helper. A response-payload twin (`response.output_json`) applies the
  same treatment where a service logs unbounded response bodies.
- Callers stop hand-assembling keys; a name change happens in one registry, not N call sites; CI
  catches drift.
- Consumers must migrate off flat/nested/message-only shapes. Adoption is opt-in per repo and staged,
  so no consumer breaks on adoption.
- The registry's `type` / `indexed` metadata lets a schema-enforcing store derive its index mapping
  from the registry (define once, derive the mapping). That export is store-specific and belongs with
  the store's own tooling, not in this store-neutral core.

## Load-bearing premises (supersede triggers)

- Powertools `append_keys` stays a shallow merge. If it gained deep-merge semantics, the nested
  ergonomics argument would reopen.
- Request-scoped context (bind at entry, clear at exit) is expressible on both backends without a
  per-request logger factory. If a `contextvars`-based filter cannot isolate concurrent requests
  cleanly on the long-running (non-Lambda) services, the backend-agnostic claim reopens.
- The value of a producer-side vocabulary does not depend on the store enforcing a schema. (It is
  higher, not lower, when the store enforces nothing.) A change of log store does not supersede this
  ADR.
