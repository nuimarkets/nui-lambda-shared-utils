# ADR-005: Explicit Secrets Manager region resolution

**Status**: Proposed
**Date**: 2026-07-13

## Context

`get_secret` in `secrets_helper.py` is the single door through which every consumer of this package
reaches AWS Secrets Manager. It is a shared credential entry point for a fleet of Lambda functions
and CLI tools that run across multiple AWS accounts and multiple regions.

A boto3 Secrets Manager client cannot be built without a region, and where that region comes from
decides whether a lookup hits the right account's secret store. The region is available in different
places depending on the runtime: a Lambda execution environment exports `AWS_REGION`; a CLI or a
differently-wired process gets it from the boto3 session (a configured profile / config file) or
`AWS_DEFAULT_REGION`; and in some runtimes it is simply absent.

Getting the region wrong is **not** a loud failure by default. A client built against the wrong
region reads a different account/region's secret namespace and typically returns
`ResourceNotFoundException`, which reads to the caller as "this secret does not exist" rather than
"you are pointed at the wrong region." A region *default* baked into the helper is the worst version
of this: it masks a missing config as one specific (usually wrong) region, and does so silently for
every consumer that never set a region. Commit `342b24b` (PR #26) is the point of record for
removing such a default from this helper.

## Decision

`get_secret` derives its region from an **explicit resolution chain, first match wins**, and never
supplies a region of its own:

1. **boto3 session region**, from `boto3.session.Session().region_name` (a configured profile or
   `AWS_DEFAULT_REGION`, which the Lambda runtime also sets). boto3 does not natively resolve
   `AWS_REGION`, so step 2 adds it explicitly for runtimes that set only that variable.
2. **`AWS_REGION`** environment variable.
3. **`AWS_DEFAULT_REGION`** environment variable.

When none of these resolve, the call **fails loudly before any client is constructed**, raising with
an explicit message that names the fix
(`"AWS region not configured for Secrets Manager lookup; set AWS_REGION or AWS_DEFAULT_REGION"`). No
client is ever built against a guessed region.

The helper carries **no hardcoded region**. A missing region is a configuration error surfaced to
the caller, not a value the package invents. This behaviour is pinned by two tests in
`tests/test_secrets_helper.py`: `test_get_secret_uses_aws_region_when_session_region_missing`
(the env-var fallback path builds the client with the configured region) and
`test_get_secret_requires_region_when_session_and_env_missing` (no session region and empty env
raises the clear error and asserts no client is created).

## Alternatives considered

- **A hidden hardcoded region default** (e.g. silently defaulting to `ap-southeast-2` inside the
  helper). This is the cheapest thing to reach for whenever a new AWS call needs a region, so it
  stays a live temptation. Rejected: it binds a store-neutral, geography-neutral package to one
  region, and any consumer running elsewhere silently reads the wrong region's secret namespace and
  gets a `ResourceNotFoundException` that reads as "secret missing," not "wrong region." Removed in
  commit `342b24b` (PR #26).
- **Best-effort silent fallthrough**: skip the region entirely and let boto3 pick whatever it can,
  or return empty on a miss. Rejected: fail-loud on missing config beats silent best-effort. A
  lookup that cannot name its own region should stop with a clear error, not guess and read from an
  unknown place.
- **Require region as an explicit function argument.** Rejected: consumers already carry region in
  the standard boto3/session and environment locations, and Lambda sets `AWS_REGION` for free.
  Threading a region parameter through every call site duplicates what the session/env already
  answer.

## Consequences

- A consumer in **any** AWS account/region works as long as region is configured the standard way
  (Lambda ambient, boto3 profile, or `AWS_REGION` / `AWS_DEFAULT_REGION`). The package assumes no
  home region.
- Misconfiguration **fails fast with a message that names the fix**, instead of a downstream
  `ResourceNotFoundException` that misattributes the cause to a missing secret and costs an operator
  a debugging session.
- Every future AWS client added to this package inherits the same rule: **no hidden region default;
  resolve explicitly or fail loud.** This is ADR-002's keep-generic principle applied to region: a
  hidden geo default is exactly the vendor/geography assumption the package forbids (see ADR-002, and
  the "Keeping the Package Generic" design principle in `AGENTS.md`).

## Load-bearing premises (supersede triggers)

- The package must run in **arbitrary AWS accounts/regions with no assumed home region**. If it were
  ever deliberately scoped to a single fixed region (a single-account, single-region product), a
  region default could be reconsidered.
- **Fail-loud on missing config is preferred over silent best-effort.** If that preference inverted
  under some "degrade quietly" runtime contract, the explicit raise would reopen.
- **Region is reachable from the boto3 session or the environment at call time.** If a supported
  runtime cannot expose region through either path, an explicit-argument region parameter would
  reopen.
