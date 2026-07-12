# ADR-002: Keep shared utilities generic

**Status**: Proposed
**Date**: 2026-07-13

## Context

This package ships to PyPI as `nui-python-shared-utils` and is imported by many independent Lambda
functions and CLI tools. `README.md` targets two audiences on purpose: the origin team, whose
defaults match, and external teams, who share none of its schema, currency, or service taxonomy. A
shared library that bakes one consumer's domain into its public surface forces every other consumer
to either carry dead weight or fork.

The pressure to bake it in is recurring and structural, not a one-time slip. It is always faster to
hardcode a caller's known table names, service list, or home currency into a "convenience" method
than to thread those through as parameters, and each such shortcut looks locally harmless. So the
constraint has to be a standing rule that every new method is measured against, not a cleanup done
once.

The line that survives that pressure is **infrastructure vs. business**. The domain-neutral half
(Slack messaging, Elasticsearch query building, database connection and query execution, CloudWatch
metrics, JWT validation, secrets, timezone) is what belongs in the shared core. The business half
(what a row means, which services exist, what currency a number is in, which status values are
terminal) is the consumer's, and it changes per deployment.

## Decision

Public APIs expose configurable infrastructure utilities and leave business-specific queries, names,
currencies, and mappings to the consumer.

- **Database access is generic.** `query()` / `execute()` take SQL and parameters. No method assumes
  a table schema, column names, or a soft-delete/status convention.
- **Values that vary by geography or deployment are required parameters or explicit configuration**,
  never defaulted to one org's convention. Currency, service name, timezone, and environment label
  are supplied by the caller.
- **No org-specific mapping constants** (service-to-emoji tables, status vocabularies) live in the
  shipped surface. A caller that wants one passes it in.

The rule is enforced continuously by `AGENTS.md`: the "Keeping the Package Generic" DO/DON'T list,
the three-question "When Adding New Features" gate ("Is this specific to NUI, or useful for any
Lambda project? / Could this be made configurable rather than hardcoded? / Can someone use this
without NUI-specific knowledge?"), the Pull Request Checklist item **"No hardcoded
organization-specific values (service names, currencies, business logic)"**, and the "Code Review
Focus Areas" ("Generic utility patterns vs vendor-specific code"). Commit `ce48031` applied the rule
(removed `get_entity_stats` / `get_record_stats`, the `SERVICE_EMOJI` map, the `currency="NZD"`
default, and value-key currency inference); that is evidence the rule bites, not the decision itself.

## Alternatives considered

- **Ship domain convenience helpers in the core** (org-specific stats queries, a service-emoji map,
  an assumed row schema). Ergonomic for the one consumer whose schema matches. Rejected: every other
  consumer imports code that queries tables it does not have, and a schema change in one consumer
  becomes a shared-library release. `get_entity_stats`/`get_record_stats` embedded `entities`/`users`
  tables, an `entity_id` foreign key, a `deleted_at` soft-delete column, and hardcoded
  `'confirmed'`/`'cancelled'` status literals: none of that is a shared library's business.
- **Keep configurable defaults but seed them with the origin org's values** (e.g. `currency="NZD"`).
  Rejected: a default silently encodes one geography. A caller in another currency gets numerically
  wrong output with no error to catch it. A required parameter forces the choice at the call site.
- **A kwargs escape hatch** (`get_record_stats(status_col=..., value_col=..., created_col=...)`).
  Rejected: the mapping kwargs prove the method is not generic, it is one schema with holes punched in
  it. A raw `query()` taking the caller's own SQL is both simpler and actually neutral.
- **Split the business helpers into a separate consumer-specific package.** Viable, and the correct
  home if such a helper is ever genuinely shared across consumers. Not built now: the removed helpers
  were thin logic wrapping a SQL string, so it is cheaper for each consumer to own its query than to
  version a shared domain layer for it.

## Consequences

- Consumers write their own domain queries and pass their own currency / service / schema values.
  More boilerplate per consumer, in exchange for zero cross-consumer coupling.
- The package is adoptable by a team with no knowledge of the origin platform, which is the third
  gate question made real.
- Reviewers get a bright-line test (does this name a table, currency, service, or status a specific
  org uses?) instead of a per-PR judgment call.
- Convenience is pushed to the consuming edges; the core stays small, which also serves the
  optional-extras bundle-size goal.
- One deliberate exception is on record: ADR-006 ships overridable `Pacific/Auckland` / `NUI_LAMBDA`
  Snowflake session defaults, governed as a bounded exception in that ADR. The bright-line test still
  holds everywhere else; a new baked geography/org default needs the same explicit, ADR-level
  justification, or it is out.

## Load-bearing premises (supersede triggers)

- **This package stays a general-purpose shared library with multiple independent consumers**
  (including external PyPI users). If it collapsed to a single internal consumer, folded into one
  application as an internal module, the generic constraint reopens: a library with one caller has no
  one to stay neutral for, and inlining that caller's schema becomes reasonable.
- **The infrastructure/business split stays clean.** Connection, query execution, formatting, and
  metrics stay domain-neutral; row meaning, service list, currency, and status vocabulary stay the
  consumer's. If a domain concept emerged that every consumer implemented identically, a shared
  domain layer (likely a separate package, not a bulge in the generic core) would be reconsidered.
- **Requiring the caller to supply currency / service / schema stays cheap enough that no default is
  worth the geography lock-in.** If a default ever became strictly necessary, it would come from
  explicit configuration, not from a baked geography or currency constant.
