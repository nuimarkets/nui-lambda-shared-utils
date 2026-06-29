"""Tests for the Anthropic (Claude) helper (nui_shared_utils.llm).

Covers:
- ``build_anthropic_client`` auth-mode selection (api_key explicit/env/secret,
  bedrock IAM) and the no-key error path,
- ``call_tool`` forced tool-use happy path, the ``None`` paths (no tool block,
  wrong tool name, non-object input, transport error, nameless tool),
- ``call_text`` text concatenation and usage extraction.

The ``anthropic`` client is mocked for the call helpers (a ``MagicMock`` with a
``messages.create``), so these are fast and offline. ``build_anthropic_client``
tests construct real SDK client objects, which is offline too (the SDK only
defers network calls to the first request); they need the ``[llm]`` extra, which
is in the ``[dev]`` extra used to run the suite.
"""

from types import SimpleNamespace
from unittest.mock import MagicMock

import anthropic
import pytest

from nui_shared_utils import llm

pytestmark = pytest.mark.unit

# A minimal, generic tool definition. No domain content (prompts/schemas stay in
# the consumer); this is just enough to exercise the forced tool-use path.
TOOL = {
    "name": "record_thing",
    "description": "Record a thing.",
    "input_schema": {
        "type": "object",
        "properties": {"score": {"type": "number"}},
        "required": ["score"],
        "additionalProperties": False,
    },
}


def _client_returning(response):
    """A mock Anthropic client whose ``messages.create`` returns ``response``."""
    client = MagicMock()
    client.messages.create.return_value = response
    return client


@pytest.fixture
def no_anthropic_env(monkeypatch):
    """Ensure ANTHROPIC_API_KEY does not leak in from the host environment."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)


# ---------------------------------------------------------------------------
# build_anthropic_client
# ---------------------------------------------------------------------------


class TestBuildAnthropicClient:
    def test_api_key_explicit_wins(self, no_anthropic_env):
        client = llm.build_anthropic_client(api_key="sk-explicit")
        assert isinstance(client, anthropic.Anthropic)
        assert client.api_key == "sk-explicit"

    def test_api_key_from_env(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-from-env")
        client = llm.build_anthropic_client()
        assert isinstance(client, anthropic.Anthropic)
        assert client.api_key == "sk-from-env"

    def test_api_key_from_secrets_manager(self, no_anthropic_env, mocker):
        get_api_key = mocker.patch.object(llm, "get_api_key", return_value="sk-from-secret")
        client = llm.build_anthropic_client(secret_name="my/anthropic-key")
        assert isinstance(client, anthropic.Anthropic)
        assert client.api_key == "sk-from-secret"
        get_api_key.assert_called_once_with("my/anthropic-key", key_field="api_key")

    def test_explicit_key_skips_secrets_manager(self, no_anthropic_env, mocker):
        get_api_key = mocker.patch.object(llm, "get_api_key", return_value="sk-from-secret")
        client = llm.build_anthropic_client(api_key="sk-explicit", secret_name="my/anthropic-key")
        assert client.api_key == "sk-explicit"
        get_api_key.assert_not_called()

    def test_api_key_missing_raises(self, no_anthropic_env):
        with pytest.raises(ValueError, match="no api_key"):
            llm.build_anthropic_client()

    def test_bedrock_mode(self, monkeypatch):
        # Dummy AWS env so boto3 (used by the Bedrock client for signing) has a
        # region and credentials to resolve; construction stays offline.
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        client = llm.build_anthropic_client(mode="bedrock", region="us-east-1")
        assert isinstance(client, anthropic.AnthropicBedrock)

    def test_unknown_mode_raises(self, no_anthropic_env):
        with pytest.raises(ValueError, match="unknown mode"):
            llm.build_anthropic_client(mode="totally-not-a-mode")


# ---------------------------------------------------------------------------
# call_tool
# ---------------------------------------------------------------------------


class TestCallTool:
    def test_happy_path_returns_tool_input(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", name="record_thing", input={"score": 0.9})],
        )
        client = _client_returning(response)

        result = llm.call_tool(client, tool=TOOL, prompt="hi", model="claude-x", max_tokens=256)

        assert result == {"score": 0.9}
        client.messages.create.assert_called_once()
        kwargs = client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-x"
        assert kwargs["max_tokens"] == 256
        assert kwargs["tools"] == [TOOL]
        assert kwargs["tool_choice"] == {"type": "tool", "name": "record_thing"}
        assert kwargs["messages"] == [{"role": "user", "content": "hi"}]
        assert "system" not in kwargs

    def test_system_prompt_is_forwarded(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", name="record_thing", input={"score": 0.1})],
        )
        client = _client_returning(response)

        llm.call_tool(client, tool=TOOL, prompt="hi", model="m", max_tokens=64, system="be terse")

        assert client.messages.create.call_args.kwargs["system"] == "be terse"

    def test_no_tool_block_returns_none(self):
        response = SimpleNamespace(content=[SimpleNamespace(type="text", text="no tool here")])
        result = llm.call_tool(_client_returning(response), tool=TOOL, prompt="hi", model="m", max_tokens=64)
        assert result is None

    def test_wrong_tool_name_returns_none(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", name="some_other_tool", input={"x": 1})],
        )
        result = llm.call_tool(_client_returning(response), tool=TOOL, prompt="hi", model="m", max_tokens=64)
        assert result is None

    def test_non_object_input_returns_none(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", name="record_thing", input="not-a-dict")],
        )
        result = llm.call_tool(_client_returning(response), tool=TOOL, prompt="hi", model="m", max_tokens=64)
        assert result is None

    def test_transport_error_returns_none(self):
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("boom")
        result = llm.call_tool(client, tool=TOOL, prompt="hi", model="m", max_tokens=64)
        assert result is None

    def test_nameless_tool_returns_none_without_calling(self):
        client = MagicMock()
        result = llm.call_tool(client, tool={"description": "no name"}, prompt="hi", model="m", max_tokens=64)
        assert result is None
        client.messages.create.assert_not_called()

    def test_null_name_returns_none_without_calling(self):
        client = MagicMock()
        result = llm.call_tool(client, tool={"name": None}, prompt="hi", model="m", max_tokens=64)
        assert result is None
        client.messages.create.assert_not_called()

    def test_non_dict_tool_returns_none_without_calling(self):
        client = MagicMock()
        result = llm.call_tool(client, tool="not-a-dict", prompt="hi", model="m", max_tokens=64)
        assert result is None
        client.messages.create.assert_not_called()


# ---------------------------------------------------------------------------
# call_text
# ---------------------------------------------------------------------------


class TestCallText:
    def test_happy_path_concatenates_text_and_extracts_usage(self):
        response = SimpleNamespace(
            content=[
                SimpleNamespace(type="text", text="hello"),
                SimpleNamespace(type="text", text=" world"),
            ],
            usage=SimpleNamespace(input_tokens=11, output_tokens=7),
        )
        client = _client_returning(response)

        result = llm.call_text(client, prompt="hi", model="claude-x", max_tokens=512)

        assert result == {"text": "hello world", "input_tokens": 11, "output_tokens": 7}
        kwargs = client.messages.create.call_args.kwargs
        assert kwargs["model"] == "claude-x"
        assert kwargs["messages"] == [{"role": "user", "content": "hi"}]
        assert "tools" not in kwargs
        assert "system" not in kwargs

    def test_system_prompt_is_forwarded(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(type="text", text="ok")],
            usage=SimpleNamespace(input_tokens=1, output_tokens=1),
        )
        client = _client_returning(response)

        llm.call_text(client, prompt="hi", model="m", max_tokens=64, system="be terse")

        assert client.messages.create.call_args.kwargs["system"] == "be terse"

    def test_no_text_blocks_returns_empty_string(self):
        response = SimpleNamespace(
            content=[SimpleNamespace(type="tool_use", name="x", input={})],
            usage=SimpleNamespace(input_tokens=3, output_tokens=0),
        )
        result = llm.call_text(_client_returning(response), prompt="hi", model="m", max_tokens=64)
        assert result == {"text": "", "input_tokens": 3, "output_tokens": 0}

    def test_transport_error_propagates(self):
        client = MagicMock()
        client.messages.create.side_effect = RuntimeError("boom")
        with pytest.raises(RuntimeError, match="boom"):
            llm.call_text(client, prompt="hi", model="m", max_tokens=64)
