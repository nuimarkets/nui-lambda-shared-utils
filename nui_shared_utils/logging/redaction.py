"""Recursive redaction for opaque log payloads (deny-list default, allow-list opt-in).

Bodies and response payloads carry unbounded, caller-controlled keys, so they are
scrubbed before being serialised into ``request.body_json`` / ``response.output_json``.
Two strategies, layered:

- **Deny-list (default)**: a base set of sensitive key-name patterns (password,
  token, secret, authorization, api_key, cookie, ...) plus the ``pii`` / ``redact``
  leaf names from the field registry, matched recursively and masked. Suitable for
  general debug payloads where most keys are legitimate and only known-sensitive
  ones must go.
- **Allow-list (opt-in via ``allow_only``)**: only the named keys survive, every
  other key is masked. PII-heavy surfaces (auth, profile, anything logging headers
  or authorization) should pass ``allow_only`` so the payload is a known safe
  subset rather than "everything minus the deny-list".

The redactor never mutates the caller's structure: it rebuilds the dict / list
spine and shares only leaf scalars (which are treated as immutable and are
serialised with ``json.dumps(default=str)`` downstream).

Documented v1 gaps (not silently accepted, tracked for v2):

- **Value-embedded secrets**: a bearer token or JWT inside a URL string, or a
  secret in a free-text value, is not caught (only key *names* are matched).
- **Leaky custom objects**: an object whose ``__str__`` / ``__repr__`` exposes a
  secret is serialised as-is.

Value-pattern masking (matching secret-shaped *values*, not just key names) is v2.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, Optional

from .fields import redaction_keys

#: Mask substituted for redacted values.
MASK = "***REDACTED***"

#: Base deny-list of sensitive key-name patterns. Deny matching is by whole
#: snake_case *word* (or phrase), so header variants like ``X-Api-Key`` and
#: camelCase like ``accessToken`` match, while ``mapping`` / ``author`` /
#: ``wildcard`` do NOT falsely match ``pin`` / ``auth`` / ``card``. Extend per
#: call via ``deny_extra`` rather than editing this set.
_BASE_DENY = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "id_token",
        "authorization",
        "auth",
        "jwt",
        "bearer",
        "api_key",
        "apikey",
        "access_key",
        "secret_key",
        "private_key",
        "session_id",
        "cookie",
        "set_cookie",
        "headers",
        "credentials",
        "card_number",
        "cvv",
        "cvc",
        "ssn",
    }
)

#: High-signal secret tokens also matched as a plain substring of the
#: separator-stripped key, so all-lowercase concatenations without a delimiter
#: (``accesstoken``, ``apitoken``, ``privatekey``) are caught too. Kept to long,
#: unambiguous words to avoid masking innocent keys (``key`` is deliberately NOT
#: here: it would mask ``monkey`` / ``primary_key``).
_SUBSTRING_DENY = frozenset(
    {
        "password",
        "passwd",
        "secret",
        "token",
        "authorization",
        "apikey",
        "credential",
        "privatekey",
        "accesskey",
        "secretkey",
    }
)

_NON_ALNUM = re.compile(r"[^a-z0-9]")
_CAMEL_1 = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_CAMEL_2 = re.compile(r"(?<=[A-Z])(?=[A-Z][a-z])")
_SEP = re.compile(r"[-.\s]+")
_MULTI_US = re.compile(r"_+")


def _to_snake(name: object) -> str:
    """Normalise a key to lowercase snake_case (camelCase and ``-`` / ``.`` unified).

    ``apiKey`` / ``X-Api-Key`` / ``api.key`` all normalise to ``api_key``, so the
    matcher is agnostic to the caller's naming style.
    """
    text = str(name)
    text = _CAMEL_1.sub("_", text)
    text = _CAMEL_2.sub("_", text)
    text = _SEP.sub("_", text.lower())
    return _MULTI_US.sub("_", text).strip("_")


def _in_deny(snake_key: str, deny: frozenset) -> bool:
    """True if ``snake_key`` matches a deny phrase.

    Two layers:

    - Whole-word / phrase match on ``_``-delimited words (avoids short-token false
      positives: ``card`` matches ``card_number`` and ``card`` but not ``wildcard``).
    - Plain substring match for the curated high-signal tokens in
      :data:`_SUBSTRING_DENY`, over the separator-stripped key, so all-lowercase
      concatenations (``accesstoken``, ``apitoken``) are caught too.
    """
    for phrase in deny:
        if (
            snake_key == phrase
            or snake_key.startswith(phrase + "_")
            or snake_key.endswith("_" + phrase)
            or ("_" + phrase + "_") in snake_key
        ):
            return True
    collapsed = _NON_ALNUM.sub("", snake_key)
    return any(token in collapsed for token in _SUBSTRING_DENY)


def _build_deny(deny_extra: Optional[Iterable[str]]) -> frozenset:
    keys = set(_BASE_DENY) | set(redaction_keys())
    if deny_extra:
        keys |= set(deny_extra)
    return frozenset(_to_snake(k) for k in keys)


def _redact(value: object, deny: frozenset, allow: Optional[frozenset]) -> object:
    if isinstance(value, dict):
        out: Dict[Any, Any] = {}
        for key, val in value.items():
            snake_key = _to_snake(key)
            if _in_deny(snake_key, deny):
                out[key] = MASK
            elif allow is not None and snake_key not in allow:
                out[key] = MASK
            else:
                out[key] = _redact(val, deny, allow)
        return out
    if isinstance(value, (list, tuple)):
        return [_redact(item, deny, allow) for item in value]
    return value


def default_redactor(
    payload: object,
    *,
    allow_only: Optional[Iterable[str]] = None,
    deny_extra: Optional[Iterable[str]] = None,
) -> object:
    """Return a redacted copy of ``payload`` without mutating the original.

    Descends dicts and lists. In the default deny-list mode, keys whose name
    matches the base pattern set or a registry-derived sensitive leaf (by whole
    snake_case word) are masked. Passing ``allow_only`` switches to allow-list
    mode: only keys whose normalised name exactly equals a named key survive at any
    depth. The deny-list still applies as a backstop, so a key that is both allowed
    and sensitive is still masked (identity fields belong in ``bind_user``, not in a
    redacted body). Non-container payloads (str, int, ``None``, ...) pass through
    unchanged.

    Args:
        payload: The structure to redact (typically a request / response body).
        allow_only: If given, keep only these key names (exact, normalised); mask
            the rest. Use on PII-heavy routes.
        deny_extra: Extra sensitive key names to add to the deny-list for this call.
    """
    deny = _build_deny(deny_extra)
    allow = frozenset(_to_snake(k) for k in allow_only) if allow_only is not None else None
    return _redact(payload, deny, allow)
