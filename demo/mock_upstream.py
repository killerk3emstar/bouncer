"""Simulated "commercial" OpenAI-compatible upstream for tests and the scripted demo.

No model runs here. Replies are either scripted (POST /mock/script pushes a FIFO queue of
responses) or a fixed, deterministic default. Every request body is recorded so tests can prove
that a secret never reached the model (GET /mock/requests).

Prices for the simulated models live in policy/bouncer.yaml (illustrative per-1M-token prices);
no paid API is ever called.

Run: uv run python -m demo.mock_upstream   (127.0.0.1:8702)
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from collections import deque
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

MODELS = ["gpt-4o-mini", "gpt-4.1", "qwen3:8b"]


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4) if text else 0


def _prompt_text(body: dict[str, Any]) -> str:
    parts = []
    for m in body.get("messages") or []:
        c = m.get("content")
        if isinstance(c, str):
            parts.append(c)
        elif isinstance(c, list):
            parts.extend(p.get("text", "") for p in c if isinstance(p, dict))
        for tc in m.get("tool_calls") or []:
            parts.append(str((tc.get("function") or {}).get("arguments", "")))
    for t in body.get("tools") or []:
        parts.append(json.dumps(t))
    return "\n".join(parts)


class MockState:
    def __init__(self) -> None:
        self.queue: deque[dict[str, Any]] = deque()
        self.requests: list[dict[str, Any]] = []

    def reset(self) -> None:
        self.queue.clear()
        self.requests.clear()

    def script(self, responses: list[dict[str, Any]], replace: bool = False) -> None:
        if replace:
            self.queue.clear()
        self.queue.extend(responses)

    def next_response(self, body: dict[str, Any]) -> dict[str, Any]:
        if self.queue:
            return self.queue.popleft()
        n = len(body.get("messages") or [])
        return {"content": f"This is a simulated reply from {body.get('model', 'the model')}. The request had {n} messages."}


def _tool_calls(item: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for i, tc in enumerate(item.get("tool_calls") or []):
        args = tc.get("arguments", {})
        out.append(
            {
                "id": tc.get("id") or f"call_{uuid.uuid4().hex[:12]}",
                "type": "function",
                "function": {
                    "name": tc["name"],
                    "arguments": args if isinstance(args, str) else json.dumps(args, ensure_ascii=False),
                },
                "index": i,
            }
        )
    return out


def create_app(state: MockState | None = None) -> FastAPI:
    state = state or MockState()
    app = FastAPI(title="Mock commercial LLM API (simulation)")
    app.state.mock = state

    @app.get("/v1/models")
    async def models() -> dict[str, Any]:
        return {"object": "list", "data": [{"id": m, "object": "model", "owned_by": "mock"} for m in MODELS]}

    @app.post("/mock/script")
    async def script(request: Request) -> dict[str, Any]:
        payload = await request.json()
        state.script(payload.get("responses") or [], bool(payload.get("replace")))
        return {"queued": len(state.queue)}

    @app.post("/mock/reset")
    async def reset() -> dict[str, Any]:
        state.reset()
        return {"ok": True}

    @app.get("/mock/requests")
    async def requests(limit: int = 50) -> dict[str, Any]:
        return {"count": len(state.requests), "requests": state.requests[-limit:]}

    @app.post("/v1/chat/completions")
    async def chat(request: Request):  # noqa: ANN202
        body = await request.json()
        state.requests.append(body)
        item = state.next_response(body)
        if item.get("delay_ms"):
            await asyncio.sleep(float(item["delay_ms"]) / 1000.0)
        if "error" in item:
            err = item["error"]
            return JSONResponse({"error": {"message": err.get("message", "mock error"), "type": "mock_error"}}, status_code=int(err.get("status", 500)))
        model = body.get("model", "mock")
        content = item.get("content")
        tool_calls = _tool_calls(item)
        prompt_tokens = _estimate_tokens(_prompt_text(body))
        completion_tokens = _estimate_tokens((content or "") + "".join(tc["function"]["arguments"] for tc in tool_calls))
        if item.get("usage"):
            prompt_tokens = item["usage"].get("prompt_tokens", prompt_tokens)
            completion_tokens = item["usage"].get("completion_tokens", completion_tokens)
        usage = {"prompt_tokens": prompt_tokens, "completion_tokens": completion_tokens, "total_tokens": prompt_tokens + completion_tokens}
        cid = "chatcmpl-mock-" + uuid.uuid4().hex[:10]
        created = int(time.time())
        finish = "tool_calls" if tool_calls else "stop"
        if not body.get("stream"):
            message: dict[str, Any] = {"role": "assistant", "content": content}
            if tool_calls:
                message["tool_calls"] = [{k: v for k, v in tc.items() if k != "index"} for tc in tool_calls]
            return {
                "id": cid,
                "object": "chat.completion",
                "created": created,
                "model": model,
                "choices": [{"index": 0, "message": message, "finish_reason": finish}],
                "usage": usage,
            }
        include_usage = bool((body.get("stream_options") or {}).get("include_usage"))
        chunk_size = int(item.get("chunk_size", 7))

        async def gen():  # noqa: ANN202
            def chunk(delta: dict[str, Any], finish_reason: str | None = None) -> str:
                obj = {
                    "id": cid,
                    "object": "chat.completion.chunk",
                    "created": created,
                    "model": model,
                    "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}],
                }
                return f"data: {json.dumps(obj, ensure_ascii=False)}\n\n"

            yield chunk({"role": "assistant", "content": ""})
            if content:
                for i in range(0, len(content), chunk_size):
                    yield chunk({"content": content[i : i + chunk_size]})
            for tc in tool_calls:
                args = tc["function"]["arguments"]
                yield chunk({"tool_calls": [{"index": tc["index"], "id": tc["id"], "type": "function", "function": {"name": tc["function"]["name"], "arguments": ""}}]})
                for i in range(0, len(args), chunk_size):
                    yield chunk({"tool_calls": [{"index": tc["index"], "function": {"arguments": args[i : i + chunk_size]}}]})
            yield chunk({}, finish)
            if include_usage:
                obj = {"id": cid, "object": "chat.completion.chunk", "created": created, "model": model, "choices": [], "usage": usage}
                yield f"data: {json.dumps(obj)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(gen(), media_type="text/event-stream")

    return app


app = create_app()

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=int(os.environ.get("MOCK_PORT", "8702")), log_level="warning")
