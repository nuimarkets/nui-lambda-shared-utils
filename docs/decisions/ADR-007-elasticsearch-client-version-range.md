# ADR-007: Support elasticsearch-py 7.17, 8.x and 9.x from one call shape

**Status**: Proposed
**Date**: 2026-07-27

## Context

The `[elasticsearch]` extra selects the client library a consumer installs alongside this
package. Because an extra is a hard requirement range, a narrow range is not a
conservative default: it is a wall. A consumer already on `elasticsearch>=8` cannot install
`nui-python-shared-utils[elasticsearch]` at all if the extra caps at `<8` -- the resolver
fails outright rather than degrading. Consumers span clusters of different vintages, so any
single-major range excludes part of the audience.

The client majors differ in how a request body is passed:

- **7.17** takes the whole request as `body=`, with URL parameters (`size`, `ignore_unavailable`)
  as separate keywords. It emits a deprecation warning for `body=` pointing at 8.x.
- **8.x / 9.x** expose body fields as first-class keywords (`query=`, `aggs=`, `size=`) and keep
  `body=` as a raw escape hatch. Mixing the two forms is the trap: passing `body=` *and* a body
  field as a keyword folds that keyword into the caller's dict (mutating it in place) and raises
  `ValueError: Received multiple values for 'size'` if the key is already present. So
  `search(index=..., body=body, size=n)` works once, then fails the second time the same body
  dict is reused with a different size.

That mixed form is what `es_client` sent, which means the `<8` cap was not merely stale: the
code as written was correct only for 7.x.

## Decision

The `[elasticsearch]` extra allows `>=7.17.0,<10.0.0`, and `es_client` sends the one call
shape all three majors accept: `size` folded into a **copy** of the caller's body
(`_body_with_size`), passed as `body=` with only genuine URL parameters
(`ignore_unavailable`) as keywords. No version sniffing, no branching.

- `search` / `aggregate` carry `size` inside the body copy; an explicit `size` argument wins
  over a `size` already in the body, and the caller's dict is never mutated.
- `count`, `cat.indices`, `info` and `cluster.health` already used a form valid on every major.
- `get_indices_info` normalises the 8.x/9.x response wrapper to a plain `list`.

`tests/test_es_client_compat.py` drives the real client with a stubbed transport (no server),
so an incompatible call shape fails as a test rather than in a consumer's Lambda. The CI
`es-compat` matrix runs it against 7.17, 8.x and 9.x, pinning 8.x at three points (8.0, 8.11
and latest) because the client routes `body=` through the parameter-rewriting fallback up to
8.11 and takes it as a declared parameter from 8.12 on.

The `<10` ceiling is the untested next major, not a known incompatibility.

## Alternatives considered

- **Cap at `<8` and tell consumers to pin down.** The status quo. Rejected: it forecloses the
  extra for anyone on a current client, and the resolver failure (`ResolutionImpossible`) gives
  no path forward short of forking.
- **Move to `>=8` only and use the native keyword API** (`query=`, `aggs=`, `size=`). Cleaner
  code, and drops a deprecated form. Rejected because it moves the wall rather than removing
  it: consumers on 7.17 clusters would be the ones locked out, and this package exists to be
  installable next to what a consumer already runs.
- **Detect the installed major at runtime and branch** (`body=` on 7.x, keywords on 8/9).
  Rejected: two call paths, one of which is exercised only on whichever major CI happens to
  install, for no behavioural gain over a shape that is already valid everywhere.
- **Mock-only tests.** The existing ES tests replace `Elasticsearch` with a `Mock`, which pins
  our call shape but cannot tell whether the installed client accepts it -- precisely the bug
  class here. Hence the stubbed-transport tests against the real client.

## Consequences

- The extra installs alongside 7.17, 8.x or 9.x, so the ES helpers are reusable by consumers on
  current clients instead of only legacy ones.
- Body dicts are safe to reuse across calls on every major; the 8.x/9.x in-place mutation is gone.
- `size` is a body field in the request we send. A consumer reading the wire format sees it in
  the body rather than the query string, on every major.
- The compat tests bind us to the real client's request-building layer, so a breaking change in a
  future client shows up as a CI failure in the `es-compat` job.

## Load-bearing premises (supersede triggers)

- **`body=` remains a supported escape hatch on 8.x/9.x.** It is documented as such today. If a
  future major removes it, the single-shape decision breaks and the choice becomes: drop 7.x and
  move to the keyword API, or branch by version.
- **Consumers still run 7.17 clients.** The whole cost here is keeping a deprecated call form
  alive. Once no supported consumer needs 7.x, raising the floor to `>=8` and moving to the
  native keyword API is strictly simpler.
- **The extra's range is a hard constraint on the consumer's environment.** If the ES helpers
  ever moved behind a runtime-optional import with no declared range, the reasoning for a wide
  range would change.
