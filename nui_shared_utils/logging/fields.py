"""Canonical structured-logging field registry (the fleet's logging contract).

This module is the single source of truth for the dotted, snake_case field names
that structured logs use. It is deliberately **stdlib-only** so it stays cheap to
import and light in a Lambda bundle: no elasticsearch, powertools, or third-party
dependency is touched here.

Two layers:

- A **generic core** registry (:data:`FIELDS`) of namespaces every web / event
  service has: ``request.*``, ``user.*``, ``route.*``, ``response.*``,
  ``error.*``, ``trace.*``, ``git.*``, plus the ``target`` routing field and the
  opaque ``request.body_json`` / ``response.output_json`` retrieval fields.
- An **extension pattern**: domain fields (``order.*``, ``tender.*``, ``api.*``,
  ``auth.*``, ...) are defined by each consumer in its own constants module and
  drift-checked with :func:`validate_fields`, so the shared package stays generic.

Each :class:`Field` carries a type, an indexed flag, a sensitivity, an owner, and
any deprecated aliases. That one structure is the derive-once source for two lists
that were otherwise hand-maintained:

- :func:`redaction_keys` -- the default redaction deny set (from ``sensitivity``).
- :func:`alias_map` -- the old-name -> canonical-name migration map (from ``aliases``).

The contract is **store-neutral**: it governs how services *emit* fields, not how
any log store indexes them. Its value is a consistent, typed field vocabulary
across the fleet, which matters under any backend. Schema-enforcing stores turn
field drift into loud errors; schema-less stores accept the drift silently and let
queries and alerts skew. A producer-side registry prevents both.

Wire shape is **dotted** (``request.method``), not nested dicts: dotted keys
survive Powertools ``append_keys`` incremental binding where nested dicts clobber
(a producer-side property, independent of the store). See
``docs/decisions/ADR-001-structured-logging-field-vocabulary.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field as _dc_field
from typing import Dict, List, Tuple

# Leaf datatypes a field may declare. These document producer intent (what a field
# is meant to hold) and give a schema-enforcing store a type to map to; a schema-less
# store coerces at query time, so the declared type is what keeps emitters honest.
_KNOWN_TYPES = frozenset({"keyword", "text", "long", "boolean", "date", "geo_point"})
# Sensitivity levels that drive default redaction.
_SENSITIVITIES = frozenset({"none", "pii", "redact"})
# A single dotted segment: lowercase snake_case, must start with a letter.
_SEGMENT_RE = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class Field:
    """One canonical log field.

    Attributes:
        key: Dotted, snake_case field name (e.g. ``"request.method"``).
        type: Leaf datatype the field is meant to hold (``keyword`` / ``text`` /
            ``long`` / ``boolean`` / ``date`` / ``geo_point``). Producer intent that
            keeps emitters consistent; not enforced by this module.
        indexed: ``False`` marks a retrieval-only field: stored for lookup but not
            meant to be queried or faceted (opaque, unbounded payloads like
            ``request.body_json``).
        sensitivity: ``none`` | ``pii`` | ``redact``. ``pii`` / ``redact`` fields
            contribute their leaf name to the default redaction deny set.
        owner: Namespace owner; ``core`` for shared fields.
        aliases: Deprecated dotted names that map to this field, used to build the
            migration / dual-read map.
    """

    key: str
    type: str
    indexed: bool = True
    sensitivity: str = "none"
    owner: str = "core"
    aliases: Tuple[str, ...] = _dc_field(default=())


class F:
    """Field-name constants for ergonomic call sites (``F.REQUEST_METHOD``).

    Every constant here has a matching entry in :data:`FIELDS`; the invariant is
    asserted by :func:`validate_registry` at import time.
    """

    # request.*
    REQUEST_ID = "request.id"
    REQUEST_METHOD = "request.method"
    REQUEST_PATH = "request.path"
    REQUEST_IP = "request.ip"
    REQUEST_BODY_JSON = "request.body_json"
    # user.*
    USER_ID = "user.id"
    USER_EMAIL = "user.email"
    USER_ORG_ID = "user.org_id"
    USER_ROLES = "user.roles"
    # response.*
    RESPONSE_STATUS = "response.status"
    RESPONSE_DURATION_MS = "response.duration_ms"
    RESPONSE_OUTPUT_JSON = "response.output_json"
    # route.*
    ROUTE_NAME = "route.name"
    ROUTE_PATH = "route.path"
    # error.*
    ERROR_TYPE = "error.type"
    ERROR_MESSAGE = "error.message"
    ERROR_STACK = "error.stack"
    # trace.*
    TRACE_ID = "trace.id"
    TRACE_SPAN_ID = "trace.span_id"
    # routing + build context
    TARGET = "target"
    GIT_COMMIT = "git.commit"
    GIT_BRANCH = "git.branch"
    GIT_TAG = "git.tag"


# The canonical registry. Keyed by dotted name; the key must equal ``Field.key``.
FIELDS: Dict[str, Field] = {
    "request.id": Field("request.id", "keyword"),
    "request.method": Field("request.method", "keyword"),
    "request.path": Field("request.path", "keyword", aliases=("request.url",)),
    "request.ip": Field("request.ip", "keyword"),
    # Opaque, retrieval-only: unbounded caller-controlled body, redacted then
    # serialised to one string so it cannot explode the index field count.
    "request.body_json": Field("request.body_json", "keyword", indexed=False, sensitivity="redact"),
    "user.id": Field("user.id", "keyword"),
    "user.email": Field("user.email", "keyword", sensitivity="pii", aliases=("request.user",)),
    # Tenant. company.* folds in here (a distinct company name, if ever needed,
    # is a consumer domain field).
    "user.org_id": Field("user.org_id", "keyword", aliases=("request.company", "request.company_id")),
    "user.roles": Field("user.roles", "keyword"),  # array; ES arrays are implicit
    "response.status": Field("response.status", "long"),
    "response.duration_ms": Field(
        "response.duration_ms",
        "long",
        aliases=("response.duration", "api.duration_ms", "duration.ms"),
    ),
    # The response twin of request.body_json (unbounded response payloads).
    "response.output_json": Field("response.output_json", "keyword", indexed=False, sensitivity="redact"),
    "route.name": Field("route.name", "keyword"),
    "route.path": Field("route.path", "keyword"),
    "error.type": Field("error.type", "keyword"),
    "error.message": Field("error.message", "text"),
    "error.stack": Field("error.stack", "text"),
    "trace.id": Field("trace.id", "keyword", aliases=("request.trace_id",)),
    "trace.span_id": Field("trace.span_id", "keyword"),
    # ES index routing. Constrain to known values at the consumer (misroute risk).
    "target": Field("target", "keyword"),
    # Optional build context; consumer-bound via bind_build_context, not automatic.
    "git.commit": Field("git.commit", "keyword"),
    "git.branch": Field("git.branch", "keyword"),
    "git.tag": Field("git.tag", "keyword"),
}


def _key_errors(key: object) -> List[str]:
    """Return a list of naming problems for ``key`` (empty means valid).

    A valid key is one or more ``.``-joined snake_case segments, each starting
    with a lowercase letter: ``target``, ``request.method``, ``user.org_id``.
    Rejects camelCase, hyphens, leading digits, and empty segments.
    """
    if not isinstance(key, str) or not key:
        return [f"{key!r}: not a non-empty string"]
    errors: List[str] = []
    for seg in key.split("."):
        if not _SEGMENT_RE.match(seg):
            errors.append(f"{key!r}: segment {seg!r} is not lowercase snake_case")
    return errors


def validate_registry() -> List[str]:
    """Validate the core :data:`FIELDS` registry, returning a list of errors.

    Checks that every key matches its ``Field.key``, is dotted snake_case, has a
    known type and sensitivity, and that aliases are globally unique and do not
    collide with any canonical key. Also asserts every :class:`F` constant is a
    registered field. An empty list means the registry is internally consistent.
    """
    errors: List[str] = []
    seen_aliases: Dict[str, str] = {}
    for key, fld in FIELDS.items():
        if fld.key != key:
            errors.append(f"{key!r}: Field.key {fld.key!r} does not match registry key")
        errors.extend(_key_errors(key))
        if fld.type not in _KNOWN_TYPES:
            errors.append(f"{key!r}: unknown type {fld.type!r}")
        if fld.sensitivity not in _SENSITIVITIES:
            errors.append(f"{key!r}: unknown sensitivity {fld.sensitivity!r}")
        for alias in fld.aliases:
            errors.extend(_key_errors(alias))
            if alias in FIELDS:
                errors.append(f"{key!r}: alias {alias!r} collides with a canonical field key")
            if alias in seen_aliases:
                errors.append(f"alias {alias!r} used by both {seen_aliases[alias]!r} and {key!r}")
            else:
                seen_aliases[alias] = key
    # Every F constant must be a real field.
    for name in dir(F):
        if name.startswith("_"):
            continue
        value = getattr(F, name)
        if isinstance(value, str) and value not in FIELDS:
            errors.append(f"F.{name} = {value!r} is not in FIELDS")
    return errors


def validate_fields(*modules: object) -> List[str]:
    """Validate that a consumer's field constants are dotted snake_case names.

    Pass one or more classes / modules whose public (non-underscore) string
    attributes are log field names. Returns a list of naming errors (empty means
    all valid), so a consumer's CI can assert ``validate_fields(OrderFields) == []``
    and catch drift from the shared convention.
    """
    errors: List[str] = []
    for mod in modules:
        label = getattr(mod, "__name__", type(mod).__name__)
        for name in dir(mod):
            if name.startswith("_"):
                continue
            value = getattr(mod, name)
            if not isinstance(value, str):
                continue
            errors.extend(f"{label}.{name}: {err}" for err in _key_errors(value))
    return errors


def redaction_keys() -> frozenset:
    """Return the leaf names of ``pii`` / ``redact`` fields for the deny set.

    These extend the redactor's base pattern list so that any payload key with a
    sensitive name (e.g. ``email`` from ``user.email``) is masked by default.
    """
    return frozenset(fld.key.split(".")[-1] for fld in FIELDS.values() if fld.sensitivity in ("pii", "redact"))


def alias_map() -> Dict[str, str]:
    """Return the ``old_name -> canonical_key`` migration map from all aliases."""
    mapping: Dict[str, str] = {}
    for fld in FIELDS.values():
        for alias in fld.aliases:
            mapping[alias] = fld.key
    return mapping


# Guard the registry at import: a malformed core registry is a bug that should
# surface the moment the logging package is first used, not silently at query time.
_REGISTRY_ERRORS = validate_registry()
if _REGISTRY_ERRORS:
    raise ValueError("Invalid logging field registry:\n  " + "\n  ".join(_REGISTRY_ERRORS))
