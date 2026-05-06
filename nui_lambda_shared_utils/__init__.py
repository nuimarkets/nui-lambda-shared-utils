"""
Backwards-compatibility shim for nui-lambda-shared-utils.

This package has been renamed to nui-python-shared-utils.
The import name has changed from nui_lambda_shared_utils to nui_shared_utils.

This shim forwards attribute access to nui_shared_utils so existing consumers
continue to work without changes. New code should use:

    from nui_shared_utils import ...

This shim will be removed in the next major version (2.0.0).

Forwarding is lazy (PEP 562 ``__getattr__``) to preserve the cold-start
optimisation in the underlying package: ``from nui_lambda_shared_utils.jwt_auth
import check_auth`` only imports ``jwt_auth`` and its dependencies, not the
full slack/es/db client surface.
"""

import warnings
from typing import Any, List

warnings.warn(
    "nui_lambda_shared_utils is deprecated. Use nui_shared_utils instead. "
    "This shim will be removed in version 2.0.0.",
    DeprecationWarning,
    stacklevel=2,
)

import nui_shared_utils as _target

__all__ = list(_target.__all__)


def __getattr__(name: str) -> Any:
    # Delegate to the new package's lazy resolver. Cache on this module so
    # subsequent accesses avoid the round-trip.
    value = getattr(_target, name)
    globals()[name] = value
    return value


def __dir__() -> List[str]:
    return sorted(set(globals()) | set(__all__))
