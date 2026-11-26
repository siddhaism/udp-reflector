import asyncio
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import server  # noqa: E402
from http_api import MAX_HEADER_BYTES, start_http_server  # noqa: E402


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 20))


def pkt(seq, mode=1):
    return server.MAGIC + bytes([1, mode]) + seq.to_bytes(8, "big") + time.time_ns().to_bytes(8, "big")


def feed(agg, addr, n=3, mode=1):
    for i in range(n):
        agg.on_packet("audio", pkt(i, mode), addr)


async def start(agg, **kw):
    def fn(h, p):
        return server.generate_summary_json(agg, time.time_ns(), filter_host=h, filter_port=p)
    srv = await start_http_server(fn, "127.0.0.1", 0, **kw)
    return srv, srv.sockets[0].getsockname()[1]


async def raw(port, data):
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(data)
    try:
        await w.drain()
    except ConnectionError:
        pass
    resp = await r.read()
    w.close()
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode().split("\r\n")
    status = int(lines[0].split()[1])
    headers = {l.split(": ", 1)[0].lower(): l.split(": ", 1)[1] for l in lines[1:]}
    return status, headers, json.loads(body) if body else None


async def get(port, target, method="GET"):
    return await raw(port, f"{method} {target} HTTP/1.1\r\nHost: x\r\n\r\n".encode())


def test_healthz_and_headers():
    async def go():
        srv, port = await start(server.Aggregator())
        st, h, body = await get(port, "/healthz")
        assert (st, body) == (200, {"status": "ok"})
        assert h["content-type"] == "application/json"
        assert h["connection"] == "close"
        srv.close()
    run(go())


def test_idle_summary_and_flows():
    async def go():
        srv, port = await start(server.Aggregator())
        assert (await get(port, "/summary"))[2] == {"idle": True, "active_flows": []}
        assert (await get(port, "/flows"))[2] == {"flows": []}
        srv.close()
    run(go())


def test_active_summary_and_flows():
    async def go():
        agg = server.Aggregator()
        feed(agg, ("10.0.0.1", 1111))
        feed(agg, ("10.0.0.2", 2222), mode=2)
        srv, port = await start(agg)
        st, _, s = await get(port, "/summary")
        assert st == 200 and s["idle"] is False and s["active_count"] == 2
        assert "aggregate" in s and len(s["flows"]) == 2
        _, _, f = await get(port, "/flows")
        assert f == {"flows": s["flows"]}
        srv.close()
    run(go())


def test_filters():
    async def go():
        agg = server.Aggregator()
        feed(agg, ("10.0.0.1", 1111))
        feed(agg, ("10.0.0.2", 2222))
        srv, port = await start(agg)
        assert (await get(port, "/summary?host=10.0.0.1"))[2]["active_count"] == 1
        assert (await get(port, "/summary?port=2222"))[2]["active_count"] == 1
        assert len((await get(port, "/flows?host=10.0.0.1&port=1111"))[2]["flows"]) == 1
        assert (await get(port, "/summary?host=9.9.9.9"))[2] == {"idle": True, "active_flows": []}
        srv.close()
    run(go())


def test_errors():
    async def go():
        srv, port = await start(server.Aggregator())
        st, _, b = await get(port, "/nope")
        assert st == 404 and "error" in b
        st, h, b = await get(port, "/summary", method="POST")
        assert st == 405 and h["allow"] == "GET" and "error" in b
        for q in ("port=abc", "port=70000", "port=-1", "port=", "host=a&host=b", "bogus=1"):
            st, _, b = await get(port, "/summary?" + q)
            assert st == 400 and "error" in b, q
        st, _, _ = await raw(port, b"garbage\r\n\r\n")
        assert st == 400
        srv.close()
    run(go())


def test_oversized_request():
    async def go():
        srv, port = await start(server.Aggregator())
        st, _, _ = await get(port, "/summary?host=" + "a" * 10000)
        assert st == 414
        hdrs = (b"Y: " + b"b" * 100 + b"\r\n") * (MAX_HEADER_BYTES // 100 + 5)
        st, _, _ = await raw(port, b"GET /healthz HTTP/1.1\r\n" + hdrs + b"\r\n")
        assert st == 431
        srv.close()
    run(go())


def test_read_timeout():
    async def go():
        srv, port = await start(server.Aggregator(), read_timeout=0.2)
        st, _, _ = await raw(port, b"GET /healthz HTTP/1.1\r\n")  # headers never finish
        assert st == 408
        srv.close()
    run(go())


def test_udp_echo_while_http_hit():
    async def go():
        agg = server.Aggregator()
        refl = server.UdpReflector("audio", "127.0.0.1", "", 0)
        transports = await refl.start(agg)
        udp_port = transports[0].get_extra_info("sockname")[1]
        srv, port = await start(agg)

        loop = asyncio.get_running_loop()
        got = asyncio.Queue()

        class P(asyncio.DatagramProtocol):
            def datagram_received(self, data, addr):
                got.put_nowait(data)

        ct, _ = await loop.create_datagram_endpoint(P, remote_addr=("127.0.0.1", udp_port))

        async def hammer():
            for _ in range(20):
                assert (await get(port, "/summary"))[0] == 200

        h = asyncio.create_task(hammer())
        for i in range(20):
            p = pkt(i)
            ct.sendto(p)
            assert await asyncio.wait_for(got.get(), 5) == p
        await h
        _, _, s = await get(port, "/summary")
        assert s["idle"] is False
        ct.close()
        srv.close()
        for t in transports:
            t.close()
    run(go())


def test_cache_ttl_with_fake_clock():
    async def go():
        calls = []
        now = [100.0]

        def fn(h, p):
            calls.append((h, p))
            return {"idle": True, "active_flows": []}

        srv = await start_http_server(fn, "127.0.0.1", 0, clock=lambda: now[0])
        port = srv.sockets[0].getsockname()[1]
        await get(port, "/summary")
        await get(port, "/flows")
        assert len(calls) == 1
        await get(port, "/summary?host=a")
        assert len(calls) == 2  # different filter key
        now[0] += 0.3
        await get(port, "/summary")
        assert len(calls) == 3
        srv.close()
    run(go())


def test_malformed_target_is_400():
    async def go():
        srv, port = await start(server.Aggregator())
        st, _, b = await get(port, "//[")
        assert st == 400 and "error" in b
        srv.close()
    run(go())


def test_bare_lf_accepted():
    async def go():
        srv, port = await start(server.Aggregator())
        st, _, b = await raw(port, b"GET /healthz HTTP/1.1\nHost: x\n\n")
        assert (st, b) == (200, {"status": "ok"})
        srv.close()
    run(go())


def test_bad_percent_and_utf8_is_400():
    async def go():
        srv, port = await start(server.Aggregator())
        for q in ("host=%zz", "host=%ff", "port=%zz", "port=%ff", "host=%", "host=%4"):
            for path in ("/summary", "/flows"):
                st, _, b = await get(port, f"{path}?{q}")
                assert st == 400 and "error" in b, (path, q)
        assert (await get(port, "/healthz?host=%zz"))[0] == 200
        srv.close()
    run(go())


def test_connection_cap_503():
    async def go():
        srv, port = await start(server.Aggregator(), max_connections=2)
        held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(2)]
        st, _, b = await get(port, "/healthz")
        assert st == 503 and "error" in b
        for r, w in held:
            w.close()
        srv.close()
    run(go())


def test_cache_unfiltered_key_survives_junk_hosts():
    async def go():
        calls = []

        def fn(h, p):
            calls.append((h, p))
            return {"idle": True, "active_flows": []}

        srv = await start_http_server(fn, "127.0.0.1", 0, clock=lambda: 100.0)
        port = srv.sockets[0].getsockname()[1]
        await get(port, "/summary")
        for i in range(200):
            await get(port, f"/summary?host=junk{i}")
        n = len(calls)
        await get(port, "/summary")
        assert len(calls) == n
        srv.close()
    run(go())


def test_raw_non_ascii_request_line_is_400():
    async def go():
        srv, port = await start(server.Aggregator())
        for path in ("/flows", "/summary", "/healthz"):
            st, _, b = await raw(port, b"GET " + path.encode() + b"?host=\xff\xfe HTTP/1.1\r\nHost: x\r\n\r\n")
            assert st == 400 and "error" in b, path
        srv.close()
    run(go())
