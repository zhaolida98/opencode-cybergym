"""Logging HTTP proxy for the LLM provider API used by opencode.

Forwards every request to UPSTREAM and appends one JSONL line per request and
per response to LOG_FILE. Works for both Anthropic-shaped (/v1/messages) and
OpenAI-shaped (/v1/chat/completions) payloads — the proxy is path-agnostic;
the Anthropic-specific rewrites below no-op on OpenAI bodies because those
don't carry a top-level `system` field.

    {"type":"request",  "seq":1, "ts":"...", "method":"POST", "path":"/v1/messages",
     "headers":{...redacted...}, "body":{...system, messages, tools...}}
    {"type":"response", "seq":1, "ts":"...", "status":200,
     "headers":{...}, "sse_events":[{"event":"...", "data":{...}}, ...]}
    {"type":"request",  "seq":2, ...}      # next turn (after a tool use)
    {"type":"response", "seq":2, ...}

Run.py launches this per agent run when --log_api is set.

Auth headers (x-api-key, authorization, anthropic-api-key) are redacted in the
log file but forwarded to the upstream untouched.
"""

import argparse
import http.server
import json
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

import httpx

REDACT = {"x-api-key", "authorization", "anthropic-api-key", "x-api-token"}
SKIP_RESP_HEADERS = {"transfer-encoding", "content-encoding", "content-length", "connection"}

# Some OpenAI-style gateways (e.g. vllm-backed) translate Anthropic top-level
# `system` into OpenAI messages and only accept a single string -- they choke
# on the list-of-text-blocks form Claude Code sends for prompt caching. Joining
# the blocks into one string is accepted by the real Anthropic API too, so we
# do this rewrite by default. Opt out by passing --no-flatten-system.
_FLATTEN_SYSTEM = True

# If not None, every POST that carries a body with a top-level `messages` list
# gets `body["temperature"]` overridden to this value before forwarding. Works
# for both Anthropic (/v1/messages) and OpenAI (/v1/chat/completions) shapes.
_TEMPERATURE: float | None = None


def _flatten_system_field(body: dict) -> bool:
    """If body['system'] is a list of text blocks, join them into one string."""
    sys = body.get("system")
    if not isinstance(sys, list):
        return False
    parts = []
    for blk in sys:
        if isinstance(blk, dict) and blk.get("type") == "text" and isinstance(blk.get("text"), str):
            parts.append(blk["text"])
        else:
            return False  # unknown shape -> don't touch it
    body["system"] = "\n\n".join(parts)
    return True


def _move_inline_system_messages(body: dict) -> bool:
    """Pull role=system entries out of messages[] and append to top-level system.

    OpenAI-style gateways only accept role in {user,assistant}; Claude Code does
    inject inline role=system reminders mid-conversation though. Concatenating
    them onto the top-level system field is the safest no-op for the real
    Anthropic API and unblocks gateways that only allow user/assistant inline.
    """
    msgs = body.get("messages")
    if not isinstance(msgs, list):
        return False
    extras = []
    kept = []
    for m in msgs:
        if isinstance(m, dict) and m.get("role") == "system":
            c = m.get("content")
            if isinstance(c, str):
                extras.append(c)
            elif isinstance(c, list):
                for blk in c:
                    if isinstance(blk, dict) and blk.get("type") == "text":
                        extras.append(blk.get("text", ""))
        else:
            kept.append(m)
    if not extras:
        return False
    body["messages"] = kept
    sys = body.get("system")
    merged = "\n\n".join(extras)
    if isinstance(sys, str) and sys:
        body["system"] = sys + "\n\n" + merged
    elif sys is None or sys == "":
        body["system"] = merged
    else:
        # Shouldn't happen if _flatten_system_field already ran; bail safely.
        return False
    return True

_LOG_FILE: Path
_UPSTREAM: str
_SEQ_LOCK = threading.Lock()
_FILE_LOCK = threading.Lock()
_SEQ = 0

# When set to N, at most N LLM requests are forwarded concurrently within this
# proxy instance (= within one task run). Set via --max-concurrent (default: no
# limit). Use --max-concurrent 1 to enforce sequential subagent execution and
# prevent parallel task-tool calls from oversubscribing the model server.
_CONCURRENCY_SEM: threading.Semaphore | None = None

# ---------------------------------------------------------------------------
# Mid-run model switch (HARDCODED). From the Nth /v1/messages call onward,
# rewrite the request to use a different model / upstream / auth. Set values
# below; leave a slot as None to keep the current value.
# ---------------------------------------------------------------------------
_SWITCH_AT_STEP = 10                          # start switch from this step (1-indexed, inclusive)
_SWITCH_MODEL: str | None = None      # e.g. "anthropic/claude-opus-4-7" or "openai/gpt-4o"
_SWITCH_UPSTREAM: str | None = None           # e.g. "https://api.other-provider.com" ; None = keep _UPSTREAM
_SWITCH_AUTH_HEADER: str | None = None        # e.g. "Bearer sk-..."; None = keep client's Authorization

_MSG_COUNT_LOCK = threading.Lock()
_MSG_COUNT = 0


def _next_msg_step() -> int:
    """Increment and return the /v1/messages call counter (1-indexed)."""
    global _MSG_COUNT
    with _MSG_COUNT_LOCK:
        _MSG_COUNT += 1
        return _MSG_COUNT


def _next_seq() -> int:
    global _SEQ
    with _SEQ_LOCK:
        _SEQ += 1
        return _SEQ


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _append(event: dict) -> None:
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with _FILE_LOCK:
        with open(_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)


def _redact(headers):
    return {k: ("<redacted>" if k.lower() in REDACT else v) for k, v in headers.items()}


def _parse_sse(buf: bytes):
    """Pop complete SSE events out of buf; return (events, remainder)."""
    events = []
    while b"\n\n" in buf:
        block, buf = buf.split(b"\n\n", 1)
        name, data_parts = None, []
        for line in block.split(b"\n"):
            if line.startswith(b"event:"):
                name = line[6:].strip().decode("utf-8", errors="replace")
            elif line.startswith(b"data:"):
                data_parts.append(line[5:].lstrip())
        if data_parts:
            data_str = b"\n".join(data_parts).decode("utf-8", errors="replace")
            try:
                data = json.loads(data_str)
            except json.JSONDecodeError:
                data = data_str
            events.append({"event": name, "data": data})
    return events, buf


class Handler(http.server.BaseHTTPRequestHandler):
    # Connection: close lets us signal end-of-response with TCP FIN instead of
    # juggling chunked-encoding framing ourselves.
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write(f"[proxy] {fmt % args}\n")
        sys.stderr.flush()

    def do_GET(self): self._handle()
    def do_POST(self): self._handle()
    def do_PUT(self): self._handle()
    def do_DELETE(self): self._handle()
    def do_PATCH(self): self._handle()
    def do_OPTIONS(self): self._handle()
    def do_HEAD(self): self._handle()

    def _handle(self):
        seq = _next_seq()
        clen = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(clen) if clen else b""

        # ---- request line ----
        req_event = {
            "type": "request",
            "seq": seq,
            "ts": _now(),
            "method": self.command,
            "path": self.path,
            "headers": _redact(dict(self.headers)),
        }
        parsed_body = None
        try:
            parsed_body = json.loads(body) if body else None
            req_event["body"] = parsed_body
        except json.JSONDecodeError:
            req_event["body_raw"] = body.decode("utf-8", errors="replace")

        # Optional: rewrites for OpenAI-style gateways (e.g. vllm). Safe no-ops
        # against the real Anthropic API. Each applied rewrite is recorded in
        # req_event['rewritten'] for traceability.
        applied: list[str] = []
        if _FLATTEN_SYSTEM and isinstance(parsed_body, dict):
            if _flatten_system_field(parsed_body):
                applied.append("flatten_system")
            if _move_inline_system_messages(parsed_body):
                applied.append("move_inline_system_messages")

        # Temperature override — only touch request bodies that clearly look
        # like a chat/messages call (top-level `messages` list), so we don't
        # mangle unrelated endpoints.
        if (
            _TEMPERATURE is not None
            and self.command == "POST"
            and isinstance(parsed_body, dict)
            and isinstance(parsed_body.get("messages"), list)
        ):
            parsed_body["temperature"] = _TEMPERATURE
            applied.append(f"temperature={_TEMPERATURE}")

        # Hardcoded mid-run model switch (see _SWITCH_* constants at top of file).
        upstream_override: str | None = None
        auth_override: str | None = None
        if self.command == "POST" and self.path.startswith("/v1/messages") and isinstance(parsed_body, dict):
            step = _next_msg_step()
            if step >= _SWITCH_AT_STEP:
                if _SWITCH_MODEL is not None:
                    parsed_body["model"] = _SWITCH_MODEL
                    applied.append(f"switch_model@step{step}")
                if _SWITCH_UPSTREAM is not None:
                    upstream_override = _SWITCH_UPSTREAM
                    applied.append(f"switch_upstream@step{step}")
                if _SWITCH_AUTH_HEADER is not None:
                    auth_override = _SWITCH_AUTH_HEADER
                    applied.append(f"switch_auth@step{step}")
            req_event["msg_step"] = step

        if applied:
            body = json.dumps(parsed_body, ensure_ascii=False).encode("utf-8")
            req_event["rewritten"] = applied
            req_event["body"] = parsed_body  # already mutated in place

        _append(req_event)

        # ---- forward + stream back ----
        upstream = upstream_override or _UPSTREAM
        url = f"{upstream.rstrip('/')}{self.path}"
        fwd_headers = {
            k: v for k, v in self.headers.items()
            if k.lower() not in ("host", "content-length")
        }
        if auth_override is not None:
            # Overwrite any client-provided auth header(s).
            for k in list(fwd_headers):
                if k.lower() in ("authorization", "x-api-key", "anthropic-api-key", "x-api-token"):
                    fwd_headers.pop(k)
            fwd_headers["Authorization"] = auth_override
        # Content-Length will be recomputed by httpx based on the (possibly rewritten) body.
        res_event = {"type": "response", "seq": seq, "ts": _now()}
        events, raw = [], bytearray()
        if _CONCURRENCY_SEM is not None:
            _CONCURRENCY_SEM.acquire()
        try:
            with httpx.Client(timeout=None) as c:
                with c.stream(self.command, url, content=body, headers=fwd_headers) as r:
                    res_event["status"] = r.status_code
                    res_event["headers"] = _redact(dict(r.headers))
                    self.send_response(r.status_code)
                    for h, v in r.headers.items():
                        if h.lower() not in SKIP_RESP_HEADERS:
                            self.send_header(h, v)
                    self.send_header("Connection", "close")
                    self.end_headers()

                    sse_buf = b""
                    for chunk in r.iter_bytes():
                        try:
                            self.wfile.write(chunk)
                            self.wfile.flush()
                        except (BrokenPipeError, ConnectionResetError):
                            break
                        raw.extend(chunk)
                        sse_buf += chunk
                        new_events, sse_buf = _parse_sse(sse_buf)
                        events.extend(new_events)
        except Exception as e:
            res_event["error"] = repr(e)
            try:
                self.send_error(502, str(e))
            except Exception:
                pass
        finally:
            if _CONCURRENCY_SEM is not None:
                _CONCURRENCY_SEM.release()

        if events:
            res_event["sse_events"] = events
        elif raw:
            try:
                res_event["body"] = json.loads(bytes(raw))
            except (json.JSONDecodeError, UnicodeDecodeError):
                res_event["body_raw"] = bytes(raw).decode("utf-8", errors="replace")
        res_event["ts_end"] = _now()
        _append(res_event)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--upstream", required=True, help="real upstream base URL")
    p.add_argument("--log-file", required=True, help="JSONL file to append every request/response to")
    p.add_argument("--flatten-system", action=argparse.BooleanOptionalAction, default=True,
                   help="Join Anthropic system-as-list-of-text-blocks into a single string before forwarding (default: on)")
    p.add_argument("--temperature", type=float, default=None,
                   help="If set, override `temperature` in every chat/messages POST body before forwarding "
                        "(both Anthropic /v1/messages and OpenAI /v1/chat/completions shapes accept this).")
    p.add_argument("--max-concurrent", type=int, default=None,
                   help="Max number of LLM requests forwarded concurrently within this proxy instance "
                        "(1 = fully sequential, enforces sequential subagent execution). Default: no limit.")
    args = p.parse_args()

    global _LOG_FILE, _UPSTREAM, _FLATTEN_SYSTEM, _TEMPERATURE, _CONCURRENCY_SEM
    _LOG_FILE = Path(args.log_file)
    _LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    _UPSTREAM = args.upstream
    _FLATTEN_SYSTEM = args.flatten_system
    _TEMPERATURE = args.temperature
    if args.max_concurrent is not None:
        _CONCURRENCY_SEM = threading.Semaphore(args.max_concurrent)

    # 0.0.0.0 so the container can reach it via host.docker.internal. On a
    # multi-user host you may want to bind to the docker bridge instead.
    server = http.server.ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    sys.stderr.write(f"[proxy] listening on :{args.port} -> {_UPSTREAM}\n")
    sys.stderr.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
