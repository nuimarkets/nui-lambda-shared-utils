"""
Regression tests for cold-start import laziness.

We run each scenario in a fresh subprocess so module-import side effects from
the rest of the test suite cannot mask a regression.
"""

import subprocess
import sys
import textwrap


def _run(script: str) -> str:
    """Execute ``script`` in a fresh Python interpreter and return stdout."""
    result = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(script)],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    return result.stdout.strip()


def test_bare_package_import_does_not_load_boto3():
    """``import nui_shared_utils`` must not transitively import boto3."""
    output = _run("""
        import sys
        import nui_shared_utils  # noqa: F401
        for mod in ("boto3", "botocore"):
            print(f"{mod}={mod in sys.modules}")
        """)
    assert "boto3=False" in output
    assert "botocore=False" in output


def test_jwt_auth_import_does_not_load_boto3():
    """``from nui_shared_utils.jwt_auth import check_auth`` must stay lazy.

    Lambdas using only JWT validation (with cached public key) should never
    pay the boto3 cold-start cost.
    """
    output = _run("""
        import sys
        from nui_shared_utils.jwt_auth import check_auth  # noqa: F401
        print(f"boto3={'boto3' in sys.modules}")
        """)
    assert "boto3=False" in output


def test_powertools_helpers_import_does_not_load_boto3():
    output = _run("""
        import sys
        from nui_shared_utils.powertools_helpers import get_powertools_logger  # noqa: F401
        print(f"boto3={'boto3' in sys.modules}")
        """)
    assert "boto3=False" in output


def test_powertools_helpers_does_not_pull_slack_sdk():
    """``powertools_helpers`` must not transitively load slack_sdk.

    Slack alerting is opt-in via ``slack_alert_channel`` on
    ``powertools_handler``; consumers using only ``get_powertools_logger``
    should not pay the slack_sdk import cost (~150ms).
    """
    output = _run("""
        import sys
        from nui_shared_utils.powertools_helpers import get_powertools_logger  # noqa: F401
        print(f"slack_sdk={'slack_sdk' in sys.modules}")
        print(f"slack_client={'nui_shared_utils.slack_client' in sys.modules}")
        """)
    assert "slack_sdk=False" in output
    assert "slack_client=False" in output


def test_legacy_shim_attribute_access_is_lazy():
    """``from nui_lambda_shared_utils import X`` must remain lazy.

    The shim used to do ``from nui_shared_utils import *`` which eagerly
    loaded every submodule. After the 1.4 lazy refactor it forwards via
    PEP 562 ``__getattr__`` so legacy consumers also benefit from
    cold-start savings.
    """
    output = _run("""
        import sys
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        from nui_lambda_shared_utils import get_powertools_logger  # noqa: F401
        print(f"boto3={'boto3' in sys.modules}")
        print(f"slack_sdk={'slack_sdk' in sys.modules}")
        print(f"db_client={'nui_shared_utils.db_client' in sys.modules}")
        print(f"es_client={'nui_shared_utils.es_client' in sys.modules}")
        """)
    assert "boto3=False" in output
    assert "slack_sdk=False" in output
    assert "db_client=False" in output
    assert "es_client=False" in output


def test_secrets_helper_loads_boto3_only_on_first_call():
    """Importing ``secrets_helper`` is cheap; the first ``get_secret`` call pays.

    Uses ``moto`` to mock AWS so the test stays network-/credential-independent.
    ``moto`` is imported after the lazy-import assertion because it pulls
    ``boto3`` transitively, which would skew ``after_import``.
    """
    output = _run("""
        import sys
        from nui_shared_utils import secrets_helper
        print(f"after_import={'boto3' in sys.modules}")
        # moto imports boto3 transitively; defer until after the lazy-import check.
        from moto import mock_aws
        with mock_aws():
            try:
                secrets_helper.get_secret("nonexistent-secret-for-test")
            except Exception:
                pass
        print(f"after_call={'boto3' in sys.modules}")
        """)
    assert "after_import=False" in output
    assert "after_call=True" in output


def test_lazy_attribute_access_returns_real_object():
    """PEP 562 ``__getattr__`` must materialise real objects, not stubs."""
    import nui_shared_utils as nui

    assert "1.50" in nui.format_currency(1.5, "NZD")
    assert nui.SlackBlockBuilder().__class__.__name__ == "SlackBlockBuilder"


def test_unknown_attribute_raises_attribute_error():
    import pytest

    import nui_shared_utils as nui

    with pytest.raises(AttributeError, match="this_does_not_exist"):
        nui.this_does_not_exist  # noqa: B018


def test_lazy_attribute_is_cached_after_first_access():
    """Once resolved, the attribute should live in ``globals()`` for fast reuse."""
    output = _run("""
        import nui_shared_utils as nui
        first = nui.format_currency
        second = nui.format_currency
        print(f"same={first is second}")
        print(f"in_globals={'format_currency' in vars(nui)}")
        """)
    assert "same=True" in output
    assert "in_globals=True" in output


def test_dir_includes_lazy_exports():
    import nui_shared_utils as nui

    names = dir(nui)
    for expected in ("SlackClient", "format_currency", "with_retry", "get_secret", "slack_setup"):
        assert expected in names, f"{expected!r} missing from dir(nui_shared_utils)"
