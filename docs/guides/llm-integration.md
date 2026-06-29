# Anthropic (Claude) Integration

The LLM helper (`nui_shared_utils.llm`) is generic plumbing for calling
Anthropic's Claude models from Lambda functions and CLI tools. It builds a
client, makes a forced tool-use call or a plain text call, and hands back the
parsed result.

It is deliberately thin. Prompts, tool schemas, model ids, and any
domain-specific processing of the result stay in your code. The helper owns auth,
the call shape, and result extraction, the parts that were being copy-pasted
across repos.

Install the optional extra:

```bash
pip install "nui-python-shared-utils[llm]"
```

`anthropic[bedrock]` covers both auth modes (API key and Bedrock IAM). The
`[bedrock]` sub-extra is what makes `anthropic.AnthropicBedrock` importable.

## What this helper is (and is not)

| In scope (lives here)                         | Out of scope (stays in your repo)              |
| --------------------------------------------- | ---------------------------------------------- |
| Build a client (API key or Bedrock IAM)       | Model id selection                             |
| Forced tool-use call + `tool_use` extraction  | Tool schemas (`input_schema`)                  |
| Text call + token-usage extraction            | Prompts and system prompts                     |
| Best-effort `None` on tool-call failure       | Validation / coercion of the returned dict     |

If you find yourself wanting to add a default model, a prompt, or a tool schema
to this module, it belongs in the consumer instead.

## Building a Client

`build_anthropic_client(mode="api_key" | "bedrock", *, api_key=None, secret_name=None, region=None, max_retries=5)`

### API-key auth (default)

Returns an `anthropic.Anthropic`. The key resolves in order:

1. explicit `api_key` argument
2. `ANTHROPIC_API_KEY` environment variable
3. AWS Secrets Manager via `secret_name` (read from the `api_key` field)

```python
from nui_shared_utils import build_anthropic_client

# Lambda: key in Secrets Manager
client = build_anthropic_client(secret_name="my-service/anthropic-key")

# Local dev: key in the environment
client = build_anthropic_client()  # reads ANTHROPIC_API_KEY

# Explicit (e.g. a key resolved from a CLI keyring or a non-default secret field)
client = build_anthropic_client(api_key=my_resolved_key)
```

If your secret stores the key under a field other than `api_key`, resolve it
yourself and pass `api_key=`:

```python
from nui_shared_utils import get_api_key, build_anthropic_client

key = get_api_key("my-service/creds", key_field="anthropic_api_key")
client = build_anthropic_client(api_key=key)
```

### Bedrock IAM auth

Returns an `anthropic.AnthropicBedrock`. No key, the Lambda's IAM role provides
access. `region` sets `aws_region`; it falls back to `AWS_REGION` /
`AWS_DEFAULT_REGION` and then to the SDK's own default region resolution.

```python
client = build_anthropic_client(mode="bedrock", region="us-east-1")
```

## Forced Tool-Use: `call_tool`

`call_tool(client, *, tool, prompt, model, max_tokens, system=None) -> dict | None`

Forces the model to answer through the named tool (`tool_choice` of type `tool`)
and returns that tool's `tool_use.input` dict. The helper only forces the call
and returns the input; it does no validation or coercion itself. Setting
`"strict": True` on your tool's `input_schema` asks the API to constrain the tool
input to that schema, but you still own validating and coercing the returned dict
(value ranges, enum membership, types) in your code.

```python
from nui_shared_utils import build_anthropic_client, call_tool

client = build_anthropic_client(secret_name="my-service/anthropic-key")

# The tool schema is yours; the helper just forces and extracts it.
classify_tool = {
    "name": "classify_item",
    "description": "Classify a support message.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "properties": {
            "category": {"type": "string", "enum": ["bug", "question", "feature"]},
            "urgency": {"type": "number", "description": "0.0 low to 1.0 urgent"},
        },
        "required": ["category", "urgency"],
        "additionalProperties": False,
    },
}

result = call_tool(
    client,
    tool=classify_tool,
    prompt="The export button does nothing and I have a deadline.",
    model="claude-haiku-4-5",   # your choice; the helper imposes no default
    max_tokens=256,
    system="You triage inbound support messages.",  # optional
)

if result is None:
    # Model error, no tool block, or a malformed result. Leave the item
    # unprocessed and let the next run retry it.
    ...
else:
    category = result["category"]   # validate/coerce in your code
    urgency = result["urgency"]
```

### Best-effort contract

`call_tool` is best-effort and **never raises** on a model or network failure. It
logs a warning and returns `None` when:

- `client.messages.create` raises any exception (transport, timeout, rate-limit, etc.),
- the response has no `tool_use` block for the named tool,
- the tool's `input` is not an object,
- the tool definition is not a dict or has no `name`.

This matches the dominant Lambda pattern: a single item failing to enrich must
not abort the batch. If a caller genuinely needs the exception (rather than a
`None`-check), that is a deliberate future addition, not the default.

## Text Calls: `call_text`

`call_text(client, *, prompt, model, max_tokens, system=None) -> dict`

Returns `{"text", "input_tokens", "output_tokens"}`. `text` is the concatenation
of all text content blocks (empty string if the response carried none). Unlike
`call_tool`, this is **not** best-effort: a transport error propagates, because
the caller wanted the text or an exception.

```python
from nui_shared_utils import build_anthropic_client, call_text

client = build_anthropic_client(mode="bedrock", region="us-east-1")

out = call_text(
    client,
    prompt="Summarize this PDF extract in two sentences:\n\n" + extract,
    model="claude-haiku-4-5",
    max_tokens=512,
)
print(out["text"])
print(out["input_tokens"], out["output_tokens"])  # for cost/usage tracking
```

## Cold Start and the Optional Extra

`anthropic` is imported at the top of `nui_shared_utils.llm`, so any use of the
helper requires the `[llm]` extra. Importing the package itself stays cheap:
`import nui_shared_utils` does not import this module (and therefore does not
import `anthropic`) until you first touch an `llm` attribute. This is the same
PEP 562 lazy-loading behaviour the rest of the package uses to keep Lambda
cold-start fast (enforced by `tests/test_lazy_imports.py`).

Without the extra installed, the top-level lazy exports resolve to `None`
(matching the other optional integrations), so a missing dependency surfaces as a
clear `None` rather than a package import failure:

```python
import nui_shared_utils as nui

if nui.build_anthropic_client is None:
    raise RuntimeError("install nui-python-shared-utils[llm] to use the LLM helper")
```

A direct `from nui_shared_utils.llm import build_anthropic_client` raises
`ImportError` when the extra is missing.

## Credential Resolution Summary

Consistent with the other shared clients (Slack, Elasticsearch, Snowflake):

1. explicit argument (`api_key=`)
2. environment variable (`ANTHROPIC_API_KEY`)
3. AWS Secrets Manager (`secret_name`, `api_key` field)

Bedrock mode uses IAM instead of any of the above. A consumer needing a CLI
keyring or GPG-backed key resolves it on its own and passes `api_key=`, the
helper does not pull in a CLI credential loader.
