# ADR-003: Lazy-load integrations to keep package import cheap

**Status**: Proposed
**Date**: 2026-07-13

## Context

This package is a shared utility layer for a fleet of AWS Lambda functions and CLI tools. Both
workloads are startup-latency sensitive: a Lambda pays the package's import cost on every cold start,
and a CLI pays it on every invocation. The package spans many integrations (Slack, Elasticsearch,
database drivers, CloudWatch/boto3, RS256 JWT via `rsa`, AWS Lambda Powertools, Snowflake, and an
Anthropic LLM helper), and most of those pull heavy third-party dependencies.

The public surface is a flat namespace: consumers write `import nui_shared_utils as nui` and reach
`nui.SlackClient`, `nui.get_secret`, `nui.bind_request`, etc. A naive way to offer that flat surface
is to import every submodule at the top of the package `__init__`, which means `import
nui_shared_utils` transitively imports boto3, the Slack SDK, elasticsearch, and everything else,
whether or not the caller touches them.

Two properties of the stack make that cost avoidable:

- **The integrations are independent.** A Lambda that only validates a JWT never needs boto3; one
  that only publishes metrics never needs the Slack SDK. Import cost is dominated by dependencies the
  caller does not use.
- **The dependencies are already optional at install time.** The package exposes per-integration
  extras (`elasticsearch`, `database`, `slack`, `jwt`, `snowflake`, `llm`, plus `all`) so a consumer
  installs only the heavy deps it needs. Eager top-level imports would either break (an uninstalled
  extra raises `ImportError` at package import) or force every consumer onto the full dependency set.

## Decision

The package's public API resolves lazily through a PEP 562 module-level `__getattr__`
(`nui_shared_utils/__init__.py`). `import nui_shared_utils` executes almost no integration code; a
heavy dependency loads only when the export that needs it is first accessed.

- **An export map, not eager imports.** `_LAZY_EXPORTS` maps each public name to its
  `(submodule, attr)` pair. On first access to a missing attribute, `__getattr__` imports that one
  submodule, pulls the attribute, and caches it into the module `globals()` so subsequent access
  skips the loader entirely (PEP 562 `__getattr__` fires only for names not already in the module
  dict).
- **Optional integrations degrade to `None`.** Submodules whose heavy dep is an optional extra are
  listed in `_OPTIONAL_SUBMODULES`; an `ImportError` during lazy resolution yields `None` instead of
  propagating, so a capability check like `if nui.SlackClient is not None` still works when the extra
  is not installed. Non-optional submodules still raise.
- **The flat surface is preserved.** `__all__` and `__dir__` enumerate the full export set, so star
  imports and interactive/tab completion behave as if everything were eagerly imported. A
  `TYPE_CHECKING`-guarded block holds the real `from .submodule import ...` statements for static type
  checkers and IDEs; that block is never executed at runtime.
- **Core boto3 use defers too.** Modules that back always-present exports (`secrets_helper`, `utils`,
  `cloudwatch_metrics`) construct their boto3 clients on first call rather than at import, so even the
  non-extra AWS path does not tax a cold start that never reaches it.

Commit `c301214` (PR #24) records the effect: `import nui_shared_utils` drops from ~700ms to ~10ms
locally. `tests/test_lazy_imports.py` locks it in, asserting in fresh subprocesses that a bare
package import loads neither boto3/botocore, nor `anthropic`, nor the `logging` subpackage, and that
representative integrations stay lazy until first touched (`jwt_auth` and `powertools_helpers` pull no
heavy dep on access, the legacy shim reaches an attribute without loading `db_client`/`es_client`, and
`secrets_helper` builds its boto3 client only on first call). The `__getattr__` mechanism makes every
export lazy; the suite pins this representative subset rather than asserting it for each integration.

## Alternatives considered

- **Eager import of every integration submodule (and its heavy deps) at package import.** The
  simplest flat-API implementation, and the standing rejected option-class. Rejected because it makes
  every consumer pay every dependency's import cost regardless of use (the ~700ms cold-start tax), and
  because it forces the full dependency set to be installed or `import nui_shared_utils` breaks,
  defeating the optional-extras model.
- **Drop the flat re-exports; require explicit submodule imports** (`from nui_shared_utils.slack_client
  import SlackClient`). Achieves laziness but breaks the established `nui.X` API and star imports for
  every caller. PEP 562 delivers the same laziness while keeping the flat surface.
- **`try/except ImportError` guards at module top.** A common optional-dependency idiom, but it still
  imports every *installed* dependency eagerly, so an environment with the `all` extra pays the full
  import cost on startup. It solves availability, not cold start.
- **Split each integration into its own distribution.** Per-integration install granularity already
  comes from extras; N packages multiply versioning and release overhead without improving import
  cost beyond what lazy loading already gives.

## Consequences

- `import nui_shared_utils` is cheap (~10ms); heavy deps load on first use of the export that needs
  them. Cold-start and CLI-startup cost scale with what a caller uses, not with what the package
  ships.
- The flat public API and star imports are unchanged, so no consumer edit is required to gain the
  saving. The legacy import shim (`nui_lambda_shared_utils`) forwards through the same PEP 562 path,
  so callers on the old name benefit too.
- New integrations must follow the pattern: add the export to `_LAZY_EXPORTS`, add the submodule to
  `_OPTIONAL_SUBMODULES` if its dep is an optional extra, mirror it in the `TYPE_CHECKING` block for
  IDE/type-checker visibility, and add a laziness assertion to `tests/test_lazy_imports.py`. A missing
  `_LAZY_EXPORTS` entry breaks runtime access; a missing `TYPE_CHECKING` entry only costs static
  completion.
- Two lists (`_LAZY_EXPORTS` and the `TYPE_CHECKING` imports) describe the same surface and must stay
  in sync by hand. `__all__` and `__dir__` derive from `_LAZY_EXPORTS`, so the runtime export set stays
  self-consistent (`test_dir_includes_lazy_exports` guards a sample of it); nothing cross-checks the
  `TYPE_CHECKING` block against `_LAZY_EXPORTS`, so a gap there costs only static completion, as above.
- Import errors surface on first use rather than at package import. For optional integrations that is
  intentional (`None` sentinel); for a genuinely missing required dependency the failure moves from
  import time to first access, which the lazy tests and normal exercise cover.

## Load-bearing premises (supersede triggers)

- Package-import latency and Lambda bundle/cold-start cost remain a real, recurring cost paid per new
  integration. If all consumers moved to always-on, long-running services where cold start is
  irrelevant, the eager-import simplicity could be reconsidered.
- The optional-extras model stays: a given integration's heavy dependency is installed only when its
  extra is requested. If every dependency became a hard requirement of the package, eager import would
  no longer risk breaking on a missing dep (though the startup-cost argument would still stand on its
  own).
- PEP 562 module-level `__getattr__` stays available on the supported interpreters. If the package
  had to run where it is unavailable, the mechanism would need replacing (explicit submodule imports)
  and this decision would reopen.
