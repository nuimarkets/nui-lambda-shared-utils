"""Generic Anthropic (Claude) client helper for AWS Lambda functions and CLI tools.

Plumbing only. Three repos independently hand-rolled the same Anthropic client +
forced-tool-use call + ``tool_use``-block parse; this consolidates that into one
tested surface. Prompts, tool schemas, model ids, and any domain post-processing
of the result stay in the consuming repo.

What lives here:

- :func:`build_anthropic_client` - API-key auth (explicit -> ``ANTHROPIC_API_KEY``
  env -> Secrets Manager) or Bedrock IAM auth, one function for both.
- :func:`call_tool` - a forced tool-use call that returns the named tool's
  ``input`` dict, or ``None`` on any model/parse failure (best-effort; never
  raises, matching the dominant Lambda enrichment pattern).
- :func:`call_text` - a plain text call returning ``{text, input_tokens,
  output_tokens}``.

The ``anthropic`` SDK is a module-level import (matching the package's other
optional integrations), so the bare ``[llm]`` extra is required to use anything
here. The cold-start guarantee is preserved by the package ``__init__`` PEP 562
lazy loader: ``import nui_shared_utils`` never imports this module (and so never
imports ``anthropic``) until a consumer first touches an ``llm`` attribute. See
``tests/test_lazy_imports.py``.

Install the extra::

    pip install 'nui-python-shared-utils[llm]'

``anthropic[bedrock]`` covers both auth modes (``anthropic.Anthropic`` for the
API key, ``anthropic.AnthropicBedrock`` for IAM); the ``[bedrock]`` sub-extra is
what makes ``AnthropicBedrock`` available.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, Optional

import anthropic

from .secrets_helper import get_api_key

log = logging.getLogger(__name__)


def build_anthropic_client(
    mode: str = "api_key",
    *,
    api_key: Optional[str] = None,
    secret_name: Optional[str] = None,
    region: Optional[str] = None,
    max_retries: int = 5,
) -> Any:
    """Build an Anthropic SDK client for the requested auth mode.

    ``mode="api_key"`` (default) returns an :class:`anthropic.Anthropic`. The key
    is resolved in order: the explicit ``api_key`` argument, then the
    ``ANTHROPIC_API_KEY`` environment variable, then
    :func:`nui_shared_utils.get_api_key` against ``secret_name`` (AWS Secrets
    Manager, ``api_key`` field). A consumer whose key lives behind a CLI keyring
    or a non-default secret field should resolve it and pass ``api_key=``.

    ``mode="bedrock"`` returns an :class:`anthropic.AnthropicBedrock` (IAM auth,
    no key). ``region`` sets ``aws_region``; it falls back to ``AWS_REGION`` /
    ``AWS_DEFAULT_REGION`` and then to the SDK's own default region resolution.

    Args:
        mode: ``"api_key"`` or ``"bedrock"``.
        api_key: Explicit Anthropic API key (api_key mode only). Skips env and
            Secrets Manager when set.
        secret_name: Secrets Manager secret name to read the key from when no
            explicit key and no env var are present (api_key mode only).
        region: AWS region for Bedrock (bedrock mode only).
        max_retries: Passed through to the SDK client (default 5).

    Raises:
        ValueError: Unknown ``mode``, or api_key mode with no key resolvable
            (no ``api_key``, no env var, and no ``secret_name``).
    """
    if mode == "bedrock":
        aws_region = region or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
        return anthropic.AnthropicBedrock(aws_region=aws_region, max_retries=max_retries)

    if mode == "api_key":
        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            if not secret_name:
                raise ValueError(
                    "build_anthropic_client(mode='api_key'): no api_key argument, "
                    "no ANTHROPIC_API_KEY env var, and no secret_name to read from "
                    "Secrets Manager"
                )
            key = get_api_key(secret_name, key_field="api_key")
        return anthropic.Anthropic(api_key=key, max_retries=max_retries)

    raise ValueError(f"build_anthropic_client: unknown mode {mode!r} (expected 'api_key' or 'bedrock')")


def call_tool(
    client: Any,
    *,
    tool: Dict[str, Any],
    prompt: str,
    model: str,
    max_tokens: int,
    system: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Make a forced tool-use call and return the named tool's ``input`` dict.

    Best-effort by design: a transport error, a malformed tool definition, a
    response with no matching ``tool_use`` block, or a non-object tool input
    logs a warning and returns ``None`` so the caller can leave the item
    unprocessed and retry on the next run. It never raises on a model or network
    failure (the dominant Lambda enrichment pattern). Validation and any
    coercion of the returned dict stay in the consumer.

    Args:
        client: An Anthropic client (from :func:`build_anthropic_client` or any
            object exposing ``messages.create``).
        tool: A single Anthropic tool definition. Must carry a ``name``.
        prompt: The user-turn prompt text.
        model: Model id (kept in the consumer; this helper imposes no default).
        max_tokens: Response token cap.
        system: Optional system prompt.

    Returns:
        The tool's ``input`` dict, or ``None`` on any failure.
    """
    if not isinstance(tool, dict):
        log.warning("call_tool: tool is not a dict; cannot force tool use")
        return None
    tool_name = str(tool.get("name") or "").strip()
    if not tool_name:
        log.warning("call_tool: tool definition has no usable 'name'; cannot force tool use")
        return None

    kwargs: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
        "tools": [tool],
        "tool_choice": {"type": "tool", "name": tool_name},
    }
    if system is not None:
        kwargs["system"] = system

    try:
        response = client.messages.create(**kwargs)
    except Exception as exc:  # noqa: BLE001 - best-effort; never abort the caller's run
        log.warning("call_tool: model call failed for tool '%s': %s", tool_name, exc)
        return None

    for block in getattr(response, "content", None) or []:
        if getattr(block, "type", None) == "tool_use" and getattr(block, "name", "") == tool_name:
            tool_input = block.input
            if isinstance(tool_input, dict):
                return tool_input
            log.warning("call_tool: tool_use input for '%s' was not an object", tool_name)
            return None

    log.warning("call_tool: response contained no tool_use block for '%s'", tool_name)
    return None


def call_text(
    client: Any,
    *,
    prompt: str,
    model: str,
    max_tokens: int,
    system: Optional[str] = None,
) -> Dict[str, Any]:
    """Make a plain text call and return the text plus token usage.

    Returns ``{"text", "input_tokens", "output_tokens"}``. ``text`` is the
    concatenation of all ``text`` content blocks (empty string if the response
    carried none). Unlike :func:`call_tool` this is not best-effort: a transport
    error propagates to the caller, who wanted the text or an exception.

    Args:
        client: An Anthropic client (from :func:`build_anthropic_client` or any
            object exposing ``messages.create``).
        prompt: The user-turn prompt text.
        model: Model id (kept in the consumer; this helper imposes no default).
        max_tokens: Response token cap.
        system: Optional system prompt.

    Returns:
        ``{"text": str, "input_tokens": int | None, "output_tokens": int | None}``.
    """
    kwargs: Dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system is not None:
        kwargs["system"] = system

    response = client.messages.create(**kwargs)
    text = "".join(
        block.text for block in (getattr(response, "content", None) or []) if getattr(block, "type", None) == "text"
    )
    usage = getattr(response, "usage", None)
    return {
        "text": text,
        "input_tokens": getattr(usage, "input_tokens", None),
        "output_tokens": getattr(usage, "output_tokens", None),
    }
