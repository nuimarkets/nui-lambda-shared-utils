"""
Backwards-compatibility shim for nui-lambda-shared-utils.

This package has been renamed to nui-python-shared-utils.
The import name has changed from nui_lambda_shared_utils to nui_shared_utils.

This shim re-exports everything from nui_shared_utils so existing consumers
continue to work without changes. New code should use:

    from nui_shared_utils import ...

This shim will be removed in the next major version (2.0.0).
"""

import warnings

warnings.warn(
    "nui_lambda_shared_utils is deprecated. Use nui_shared_utils instead. "
    "This shim will be removed in version 2.0.0.",
    DeprecationWarning,
    stacklevel=2,
)

from nui_shared_utils import *  # noqa: F401,F403
from nui_shared_utils import __all__  # noqa: F401
