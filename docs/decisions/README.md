# Architecture Decision Records

Decisions that outlive any single change: the "why" behind a choice future readers will want to
verify, challenge, or build on. These are scoped to this package.

## Format

```markdown
# ADR-NNN: <Short title>

**Status**: Proposed | Accepted | Superseded by ADR-XXX
**Date**: YYYY-MM-DD

## Context      # the situation forcing the decision (present tense, the standing rationale)
## Decision     # what we decide to do
## Alternatives considered
## Consequences  # what this makes easier, harder, or rules out
```

Keep each ADR under two pages. Longer than that means it is a plan, not an ADR.

## Index

| # | Decision | Status | Date |
|---|----------|--------|------|
| [001](ADR-001-structured-logging-field-vocabulary.md) | Structured logging field vocabulary (dotted registry + helpers + consistency test) | Proposed | 2026-07-11 |
| [002](ADR-002-keep-shared-utilities-generic.md) | Keep shared utilities generic: configurable infrastructure, business queries/names/currencies to the consumer | Proposed | 2026-07-13 |
| [003](ADR-003-lazy-load-integrations.md) | Lazy-load integrations via PEP 562 so package import stays cheap; heavy deps load on first use | Proposed | 2026-07-13 |
| [004](ADR-004-credential-resolution-precedence.md) | Credential resolution precedence: explicit dict, then env vars, then Secrets Manager | Proposed | 2026-07-13 |
| [005](ADR-005-explicit-secrets-manager-region.md) | Resolve the Secrets Manager region explicitly (session, then env); no hidden default, fail loud | Proposed | 2026-07-13 |
| [006](ADR-006-snowflake-sql-api-client.md) | Snowflake access via the pure-Python SQL API client, not the native connector | Proposed | 2026-07-13 |
| [007](ADR-007-elasticsearch-client-version-range.md) | Support elasticsearch-py 7.17, 8.x and 9.x from one call shape | Proposed | 2026-07-27 |
