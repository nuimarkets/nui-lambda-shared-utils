"""Structured logging contract: canonical field registry + backend-agnostic binders.

The fleet's dotted, snake_case logging vocabulary and the helpers that emit it.
Stdlib-only, so importing this package pulls in no third-party dependency (the
Powertools binder calls ``append_keys`` / ``remove_keys`` on a logger the caller
constructs; it never imports ``aws_lambda_powertools`` itself).

Typical use::

    from nui_shared_utils.logging import F, stdlib_binder, bind_request, bind_user

    binder = stdlib_binder(logger)
    with binder.request_scope():
        bind_request(binder, method="POST", path="/orders", request_id=rid)
        bind_user(binder, id=u.id, email=u.email, org_id=u.org_id)
        logger.info("response", extra={F.RESPONSE_STATUS: 200})

See ``docs/guides/structured-logging-contract.md`` for the full guide and
``docs/decisions/ADR-001-structured-logging-field-vocabulary.md`` for the rationale.
"""

from .binding import (
    PowertoolsBinder,
    StdlibBinder,
    bind_build_context,
    bind_request,
    bind_user,
    log_exception,
    powertools_binder,
    request_body_fields,
    response_output_fields,
    stdlib_binder,
)
from .fields import (
    FIELDS,
    F,
    Field,
    alias_map,
    redaction_keys,
    validate_fields,
    validate_registry,
)
from .redaction import MASK, default_redactor

__all__ = [
    # registry
    "F",
    "FIELDS",
    "Field",
    "validate_fields",
    "validate_registry",
    "redaction_keys",
    "alias_map",
    # redaction
    "default_redactor",
    "MASK",
    # binders + helpers
    "powertools_binder",
    "stdlib_binder",
    "PowertoolsBinder",
    "StdlibBinder",
    "bind_request",
    "bind_user",
    "bind_build_context",
    "log_exception",
    "request_body_fields",
    "response_output_fields",
]
