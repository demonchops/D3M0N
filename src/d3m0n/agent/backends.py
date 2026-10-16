"""Pluggable LLM backends behind one call shape, so graph.py's
plan_and_act loop doesn't need to know or care which one is in use.

Two backends:
- Claude via the Anthropic API (anthropic.Anthropic() itself) — the
  default, needs ANTHROPIC_API_KEY.
- OpenAICompatibleClient: any self-hosted server speaking the OpenAI
  chat-completions protocol (Ollama, llama.cpp's server, vLLM, LM
  Studio, text-generation-webui, ...) — no API key, runs fully
  self-contained.

The internal message/content-block representation stays Anthropic-
shaped throughout (blocks with "type" in {"text","tool_use","tool_result"},
model_dump()-able) regardless of backend. OpenAICompatibleClient
translates to/from OpenAI's tool-calling shape at the call boundary, so
graph.py — including the prompt-caching logic (cache_control keys just
ride along unused when talking to a local server, harmless) — never has
to change based on which backend is configured.

What does NOT change with a local backend: tool-call dispatch still goes
through registry.run_tool()'s scope enforcement regardless of which
model produced the call. That boundary was always enforced independent
of the model's own behavior, by design — a local model is not
necessarily as reliable about following the system prompt's own stated
limits as Claude is, which is exactly why that enforcement never relied
on the model cooperating in the first place.
"""

from __future__ import annotations

import json

import requests


class Block:
    """Attribute-accessible content block, duck-typing the slice of the
    Anthropic SDK's block interface graph.py relies on (.type, .text,
    .id, .name, .input, .model_dump()) so plan_and_act doesn't care
    which backend produced it."""

    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

    def model_dump(self) -> dict:
        return dict(self.__dict__)


class _FakeResponse:
    def __init__(self, content: list[Block]):
        self.content = content


class _MessagesNamespace:
    def __init__(self, create_fn):
        self.create = create_fn


def _to_openai_system(system) -> str:
    if isinstance(system, str):
        return system
    return "\n\n".join(b.get("text", "") for b in system if isinstance(b, dict))


def _to_openai_tools(tools: list[dict]) -> list[dict]:
    """Anthropic tool schema -> OpenAI function-calling schema. Any
    cache_control key (Anthropic-specific) is simply not copied over —
    a local server has no use for it and nothing here depends on it."""
    return [
        {
            "type": "function",
            "function": {
                "name": t["name"],
                "description": t.get("description", ""),
                "parameters": t.get("input_schema", {"type": "object", "properties": {}}),
            },
        }
        for t in tools
    ]


def _to_openai_messages(messages: list[dict]) -> list[dict]:
    """Anthropic-shaped message history -> OpenAI's flat per-role list.
    A stray cache_control key on any block is simply never read here —
    harmless to leave in place."""
    openai_messages = []
    for msg in messages:
        role = msg["role"]
        content = msg["content"]
        if isinstance(content, str):
            openai_messages.append({"role": role, "content": content})
            continue

        if role == "assistant":
            text_parts = [b["text"] for b in content if b.get("type") == "text"]
            tool_use_blocks = [b for b in content if b.get("type") == "tool_use"]
            entry: dict = {"role": "assistant", "content": " ".join(text_parts) or None}
            if tool_use_blocks:
                entry["tool_calls"] = [
                    {
                        "id": b["id"],
                        "type": "function",
                        "function": {"name": b["name"], "arguments": json.dumps(b.get("input", {}))},
                    }
                    for b in tool_use_blocks
                ]
            openai_messages.append(entry)
        else:
            # role == "user": either plain text, or one-or-more tool_result
            # blocks, each of which OpenAI expects as its OWN "tool"-role
            # message rather than nested inside one user message.
            for b in content:
                if b.get("type") == "tool_result":
                    openai_messages.append(
                        {
                            "role": "tool",
                            "tool_call_id": b["tool_use_id"],
                            "content": str(b.get("content", "")),
                        }
                    )
                elif b.get("type") == "text":
                    openai_messages.append({"role": "user", "content": b["text"]})
    return openai_messages


def _from_openai_response(data: dict) -> list[Block]:
    try:
        message = data["choices"][0]["message"]
    except (KeyError, IndexError, TypeError) as exc:
        raise RuntimeError(f"Local model returned an unexpected response shape: {exc}; got: {data!r}")

    blocks: list[Block] = []
    if message.get("content"):
        blocks.append(Block(type="text", text=message["content"]))
    for tc in message.get("tool_calls") or []:
        try:
            args = json.loads(tc["function"]["arguments"] or "{}")
        except (json.JSONDecodeError, KeyError):
            args = {}
        blocks.append(
            Block(type="tool_use", id=tc.get("id", ""), name=tc["function"]["name"], input=args)
        )
    return blocks


class OpenAICompatibleClient:
    """Duck-types anthropic.Anthropic()'s surface — .messages.create(...)
    returning something with a .content list of Blocks — against a
    self-hosted OpenAI-compatible chat-completions endpoint. The model
    MUST support genuine tool/function calling for this agent to do
    anything useful; a model that only emits plain text will never call
    a tool and the run will just exhaust its step budget doing nothing.
    """

    def __init__(self, base_url: str, api_key: str = "not-needed", timeout_s: int = 120):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout_s = timeout_s
        self.messages = _MessagesNamespace(self._create)

    def _create(self, *, model, max_tokens, system, tools, messages):
        payload = {
            "model": model,
            "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": _to_openai_system(system)}]
            + _to_openai_messages(messages),
        }
        openai_tools = _to_openai_tools(tools)
        if openai_tools:
            payload["tools"] = openai_tools
            payload["tool_choice"] = "auto"

        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        try:
            resp = requests.post(
                f"{self.base_url}/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout_s,
            )
            resp.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(
                f"Could not reach the local model at {self.base_url!r}: {exc}. Is it running, "
                "and does it actually implement the OpenAI chat-completions protocol?"
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise RuntimeError(f"Local model returned a non-JSON response: {exc}")

        return _FakeResponse(content=_from_openai_response(data))
