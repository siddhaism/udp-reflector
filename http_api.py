"""Read-only, opt-in REST API for the server, built on asyncio streams.

One response per connection (Connection: close). Only GET is served.
"""
import asyncio
import json
import re
import time
from urllib.parse import parse_qs, urlsplit

MAX_REQUEST_LINE = 2048
MAX_HEADER_BYTES = 8192
READ_TIMEOUT_S = 5.0
# Known limitation: this cap counts idle connections that have not yet sent a
# request (up to read_timeout), so a client can hold all slots. Only suitable
# on loopback or behind a firewall.
MAX_CONNECTIONS = 64
CACHE_TTL_S = 0.25
CACHE_MAX_FILTERED = 64  # filtered keys kept (LRU); the unfiltered key is pinned
_BAD_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")

_REASONS = {
    200: "OK", 400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
    408: "Request Timeout", 503: "Service Unavailable", 414: "URI Too Long", 431: "Request Header Fields Too Large",
    500: "Internal Server Error",
}


class _HttpError(Exception):
    def __init__(self, status, message, headers=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


def _response(status, obj, extra_headers=None):
    body = json.dumps(obj).encode()
    head = [
        f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}",
        "Content-Type: application/json",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    for k, v in (extra_headers or {}).items():
        head.append(f"{k}: {v}")
    return ("\r\n".join(head) + "\r\n\r\n").encode() + body


async def _read_request(reader):
    """Return (method, target). Raises _HttpError on malformed/oversized input."""
    try:
        line = await reader.readuntil(b"\n")
    except asyncio.LimitOverrunError:
        raise _HttpError(414, "request line too long")
    except asyncio.IncompleteReadError:
        raise _HttpError(400, "incomplete request")
    if len(line) > MAX_REQUEST_LINE:
        raise _HttpError(414, "request line too long")
    parts = line.decode("latin-1").rstrip("\r\n").split(" ")
    if len(parts) != 3 or not parts[2].startswith("HTTP/"):
        raise _HttpError(400, "malformed request line")
    total = 0
    while True:
        try:
            h = await reader.readuntil(b"\n")
        except asyncio.LimitOverrunError:
            raise _HttpError(431, "headers too large")
        except asyncio.IncompleteReadError:
            raise _HttpError(400, "incomplete headers")
        total += len(h)
        if total > MAX_HEADER_BYTES:
            raise _HttpError(431, "headers too large")
        if h in (b"\r\n", b"\n"):
            break
    return parts[0], parts[1]


def _single(qs, name):
    vals = qs.get(name)
    if vals is None:
        return None
    if len(vals) != 1 or vals[0] == "":
        raise _HttpError(400, f"invalid query parameter: {name}")
    return vals[0]


def _route(method, target, summary_fn):
    if method != "GET":
        raise _HttpError(405, "method not allowed", {"Allow": "GET"})
    try:
        split = urlsplit(target)
    except ValueError:
        raise _HttpError(400, "malformed request target")
    path = split.path
    if path not in ("/healthz", "/summary", "/flows"):
        raise _HttpError(404, "not found")
    if path == "/healthz":
        return {"status": "ok"}
    if _BAD_ESCAPE.search(split.query):
        raise _HttpError(400, "invalid percent-encoding in query")
    try:
        qs = parse_qs(split.query, keep_blank_values=True, errors="strict")
    except ValueError:
        raise _HttpError(400, "invalid query encoding")
    unknown = set(qs) - {"host", "port"}
    if unknown:
        raise _HttpError(400, f"unknown query parameter: {sorted(unknown)[0]}")
    host = _single(qs, "host")
    port_s = _single(qs, "port")
    port = None
    if port_s is not None:
        if not port_s.isascii() or not port_s.isdigit() or not 0 <= int(port_s) <= 65535:
            raise _HttpError(400, "invalid query parameter: port")
        port = int(port_s)
    summary = summary_fn(host, port)
    if path == "/summary":
        return summary
    return {"flows": summary.get("flows", [])}


async def _handle(reader, writer, summary_fn, read_timeout, state, max_connections):
    if state["active"] >= max_connections:
        try:
            writer.write(_response(503, {"error": "too many connections"}))
            await asyncio.wait_for(writer.drain(), read_timeout)
            # Best-effort drain of the pending request so close does not RST the 503.
            await asyncio.wait_for(reader.read(MAX_HEADER_BYTES), 0.1)
        except Exception:
            pass
        finally:
            writer.close()
        return
    state["active"] += 1
    try:
        try:
            method, target = await asyncio.wait_for(_read_request(reader), read_timeout)
            data = _response(200, _route(method, target, summary_fn))
        except asyncio.TimeoutError:
            data = _response(408, {"error": "request timeout"})
        except _HttpError as e:
            data = _response(e.status, {"error": e.message}, e.headers)
        except Exception:
            data = _response(500, {"error": "internal error"})
        writer.write(data)
        await asyncio.wait_for(writer.drain(), read_timeout)
    except Exception:
        pass
    finally:
        state["active"] -= 1
        try:
            writer.close()
        except Exception:
            pass


def _cached(summary_fn, ttl, clock):
    cache = {}

    def fn(host, port):
        now = clock()
        hit = cache.get((host, port))
        if hit is not None and now - hit[0] < ttl:
            if (host, port) != (None, None):
                cache[(host, port)] = cache.pop((host, port))  # LRU touch
            return hit[1]
        val = summary_fn(host, port)
        key = (host, port)
        cache[key] = (now, val)
        filtered = [k for k in cache if k != (None, None)]
        # Pin the unfiltered key; evict oldest filtered keys beyond the cap.
        for k in filtered[:max(0, len(filtered) - CACHE_MAX_FILTERED)]:
            del cache[k]
        return val
    return fn


async def start_http_server(summary_fn, host="127.0.0.1", port=0, read_timeout=READ_TIMEOUT_S,
                            max_connections=MAX_CONNECTIONS, cache_ttl=CACHE_TTL_S, clock=time.monotonic):
    """Start the REST server.

    summary_fn(filter_host, filter_port) must return the generate_summary_json
    dict (never None). Returns the asyncio.Server.
    """
    fn = _cached(summary_fn, cache_ttl, clock)
    state = {"active": 0}
    return await asyncio.start_server(
        lambda r, w: _handle(r, w, fn, read_timeout, state, max_connections),
        host, port, limit=MAX_REQUEST_LINE,
    )
