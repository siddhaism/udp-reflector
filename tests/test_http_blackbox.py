"""Black-box tests of the REST API against a real server.py subprocess."""
import json
import os
import socket
import struct
import subprocess
import sys
import threading
import time

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MAGIC = b"MTP1"


def _free(kind):
    s = socket.socket(socket.AF_INET, kind)
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _packet(mode, seq, size=64):
    hdr = MAGIC + struct.pack(">BBQQ", 1, mode, seq, time.time_ns())
    return hdr + b"\x00" * (size - len(hdr))


class Srv:
    pass


@pytest.fixture(scope="module")
def srv():
    s = Srv()
    s.audio = _free(socket.SOCK_DGRAM)
    s.video = _free(socket.SOCK_DGRAM)
    tcp = _free(socket.SOCK_STREAM)
    s.proc = subprocess.Popen(
        [sys.executable, "-u", os.path.join(ROOT, "server.py"),
         "--tcp-host-v4", "127.0.0.1", "--tcp-host-v6", "", "--tcp-port", str(tcp),
         "--udp-host-v4", "127.0.0.1", "--udp-host-v6", "",
         "--audio-port", str(s.audio), "--video-port", str(s.video),
         "--idle-ttl", "60", "--http-port", "0"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, cwd=ROOT)
    s.lines = []
    s.http = None
    ready = threading.Event()

    def pump():
        for line in s.proc.stdout:
            s.lines.append(line)
            if "HTTP API listening on" in line and s.http is None:
                s.http = int(line.strip().rsplit(":", 1)[1])
                ready.set()
        ready.set()

    threading.Thread(target=pump, daemon=True).start()
    if not ready.wait(30) or s.http is None:
        s.proc.kill()
        pytest.fail("server did not report HTTP port: %r" % s.lines)
    yield s
    s.proc.kill()
    s.proc.wait(10)


def raw(srv, data, timeout=10, shutdown=False):
    """Send raw bytes, return the full response bytes."""
    with socket.create_connection(("127.0.0.1", srv.http), timeout=timeout) as c:
        c.sendall(data)
        if shutdown:
            c.shutdown(socket.SHUT_WR)
        buf = b""
        try:
            while True:
                d = c.recv(65536)
                if not d:
                    break
                buf += d
        except (ConnectionResetError, socket.timeout):
            pass
    return buf


def parse(resp):
    head, _, body = resp.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for l in lines[1:]:
        k, _, v = l.partition(":")
        headers[k.strip().lower()] = v.strip()
    return status, headers, body


def get(srv, target, version="HTTP/1.1", method="GET"):
    req = ("%s %s %s\r\nHost: x\r\n\r\n" % (method, target, version)).encode("latin-1")
    return parse(raw(srv, req))


def jget(srv, target):
    st, h, b = get(srv, target)
    return st, h, json.loads(b)


def send_udp(port, mode, seqs, sock=None):
    s = sock or socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(10)
    for q in seqs:
        pkt = _packet(mode, q)
        s.sendto(pkt, ("127.0.0.1", port))
        data, _ = s.recvfrom(4096)
        assert data == pkt
    return s


def wait_for(fn, what, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        v = fn()
        if v:
            return v
        time.sleep(0.02)
    pytest.fail("timeout waiting for " + what)


# ---------------------------------------------------------------- basics

def test_healthz(srv):
    st, h, body = get(srv, "/healthz")
    assert st == 200
    assert json.loads(body) == {"status": "ok"}
    assert "application/json" in h["content-type"]
    assert h["connection"].lower() == "close"
    st, _, body = get(srv, "/healthz?x=1&&%zz")
    assert st == 200 and json.loads(body) == {"status": "ok"}


def test_idle_before_traffic(srv):
    # Must run before any test sends UDP (tests below use ordering by file position).
    st, h, d = jget(srv, "/summary")
    assert st == 200
    assert d == {"idle": True, "active_flows": []}
    assert "application/json" in h["content-type"]
    st, _, d = jget(srv, "/flows")
    assert (st, d) == (200, {"flows": []})


def test_active_summary_and_flows_and_filters(srv):
    sock = send_udp(srv.audio, 1, range(5))
    port = sock.getsockname()[1]

    def active():
        st, _, d = jget(srv, "/summary")
        return d if d.get("idle") is False else None

    d = wait_for(active, "active summary")
    assert d["idle"] is False
    assert d["active_count"] >= 1
    assert isinstance(d["flows"], list) and len(d["flows"]) == d["active_count"]
    assert "aggregate" in d

    st, _, f = jget(srv, "/flows")
    assert st == 200 and list(f) == ["flows"] and len(f["flows"]) >= 1
    flow = f["flows"][0]
    # discover the key names used for host/port in a flow entry
    hk = next(k for k in flow if flow[k] == "127.0.0.1")
    pk = next(k for k in flow if flow[k] == port and k != hk)

    st, _, f = jget(srv, "/flows?host=127.0.0.1&port=%d" % port)
    assert st == 200 and len(f["flows"]) == 1
    assert f["flows"][0][pk] == port
    st, _, f = jget(srv, "/flows?host=127.0.0.1")
    assert st == 200 and len(f["flows"]) >= 1
    st, _, f = jget(srv, "/flows?host=127.0.0.2")
    assert (st, f) == (200, {"flows": []})
    other = 1 if port != 1 else 2
    st, _, f = jget(srv, "/flows?port=%d" % other)
    assert (st, f) == (200, {"flows": []})
    st, _, f = jget(srv, "/flows?port=%d" % port)
    assert st == 200 and len(f["flows"]) == 1
    # exact match, not prefix/substring
    st, _, f = jget(srv, "/flows?host=127.0.0.")
    assert f == {"flows": []}
    # filtered summary with no match is idle form
    st, _, d = jget(srv, "/summary?host=10.9.9.9")
    assert st == 200 and d.get("idle") is True
    st, _, d = jget(srv, "/summary?port=%d" % port)
    assert st == 200 and d["idle"] is False and d["active_count"] == 1
    sock.close()


# ---------------------------------------------------------------- 400s

@pytest.mark.parametrize("target", [
    "/flows?foo=1",
    "/summary?hostx=1",
    "/flows?host=a&host=b",
    "/flows?port=1&port=2",
    "/flows?host=",
    "/flows?port=",
    "/summary?host=",
    "/flows?port=abc",
    "/flows?port=-1",
    "/flows?port=65536",
    "/flows?port=99999999999999999999",
    "/flows?port=+5",
    "/flows?port=1.5",
    "/flows?port=%D9%A5",       # ARABIC-INDIC DIGIT FIVE (non-ASCII digit)
    "/flows?port=%EF%BC%95",    # fullwidth 5
    "/flows?port=%20",
    "/flows?host=%zz",
    "/flows?host=%",
    "/flows?host=%4",
    "/flows?host=%FF",
    "/flows?host=%C0%AF",
    "/summary?port=%ZZ",
])
def test_bad_query_400(srv, target):
    st, h, body = get(srv, target)
    assert st == 400, (target, st, body)
    assert "application/json" in h["content-type"]
    json.loads(body)


@pytest.mark.parametrize("port", ["0", "1", "65535", "00080", "%35%30"])
def test_valid_ports_accepted(srv, port):
    st, _, d = jget(srv, "/flows?port=" + port)
    assert st == 200 and "flows" in d


def test_raw_invalid_utf8_in_query(srv):
    resp = raw(srv, b"GET /flows?host=\xff\xfe HTTP/1.1\r\nHost: x\r\n\r\n")
    assert parse(resp)[0] == 400


# ---------------------------------------------------------------- routing

@pytest.mark.parametrize("target", ["/", "/nope", "/healthz/", "/summary/", "/flows/", "/Summary", "/flows/x", "/healthz.json"])
def test_404(srv, target):
    st, h, body = get(srv, target)
    assert st == 404, target
    json.loads(body)


@pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "FOO"])
def test_405(srv, method):
    resp = raw(srv, ("%s /healthz HTTP/1.1\r\nHost: x\r\n\r\n" % method).encode())
    st, h, _ = parse(resp)
    assert st == 405
    assert h["allow"] == "GET"


def test_405_post_with_body(srv):
    st, h, _ = parse(raw(srv, b"POST /summary HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n\r\nabcd"))
    assert st == 405 and h["allow"] == "GET"


def test_414_long_request_line(srv):
    st, _, _ = parse(raw(srv, b"GET /" + b"a" * 3000 + b" HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert st == 414
    st, _, _ = parse(raw(srv, b"GET /healthz?" + b"a" * 5000))  # never terminated
    assert st == 414


def test_request_line_just_under_limit_not_414(srv):
    pad = 2048 - len("GET /flows?host= HTTP/1.1\r\n") - 10
    st, _, _ = parse(raw(srv, b"GET /flows?host=" + b"a" * pad + b" HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert st == 200


def test_431_large_headers(srv):
    req = b"GET /healthz HTTP/1.1\r\n" + b"X-Pad: " + b"a" * 9000 + b"\r\n\r\n"
    assert parse(raw(srv, req))[0] == 431
    many = b"GET /healthz HTTP/1.1\r\n" + b"".join(b"X-%d: %s\r\n" % (i, b"v" * 100) for i in range(100)) + b"\r\n"
    assert parse(raw(srv, many))[0] == 431


@pytest.mark.parametrize("line", [
    b"GET //[ HTTP/1.1",
    b"GET http://[ HTTP/1.1",
    b"GET http://[::1 /summary HTTP/1.1",
    b"GARBAGE",
    b"GET",
    b"GET /healthz",
    b"GET  /healthz  HTTP/1.1",
    b"\x00\x01\x02\x03",
    b"GET /healthz HTTP/9.9",
    b"GET healthz HTTP/1.1",
    b"GET /\xff\xfe HTTP/1.1",
    b"GET http://%zz/ HTTP/1.1",
    b"GET //:99999999/x HTTP/1.1",
    b"GET /healthz HTTP/1.1 extra",
])
def test_malformed_never_500(srv, line):
    resp = raw(srv, line + b"\r\nHost: x\r\n\r\n", shutdown=True)
    if resp:
        st, _, _ = parse(resp)
        assert st != 500 and 400 <= st < 500 or st == 200, (line, st)
    # server still healthy
    assert get(srv, "/healthz")[0] == 200


@pytest.mark.parametrize("line", [b"GET //[ HTTP/1.1", b"GET http://[ HTTP/1.1", b"GET http://[::1 /summary HTTP/1.1"])
def test_bracket_targets_are_400(srv, line):
    st, _, body = parse(raw(srv, line + b"\r\n\r\n"))
    assert st == 400
    json.loads(body)


def test_bare_lf_accepted(srv):
    st, _, body = parse(raw(srv, b"GET /healthz HTTP/1.1\nHost: x\n\n"))
    assert st == 200 and json.loads(body) == {"status": "ok"}
    st, _, body = parse(raw(srv, b"GET /flows?host=nobody HTTP/1.0\n\n"))
    assert st == 200 and json.loads(body) == {"flows": []}


def test_absolute_form_routes_by_path(srv):
    st, _, body = parse(raw(srv, b"GET http://example.com/healthz HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert st == 200 and json.loads(body) == {"status": "ok"}
    st, _, body = parse(raw(srv, b"GET http://example.com:8080/flows?host=nobody HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert st == 200 and json.loads(body) == {"flows": []}
    st, _, _ = parse(raw(srv, b"GET http://example.com/nope HTTP/1.1\r\nHost: x\r\n\r\n"))
    assert st == 404


def test_http10_and_no_headers(srv):
    st, h, _ = parse(raw(srv, b"GET /healthz HTTP/1.0\r\n\r\n"))
    assert st == 200 and h["connection"].lower() == "close"


def test_extra_headers_ignored(srv):
    st, _, _ = parse(raw(srv, b"GET /healthz HTTP/1.1\r\nHost: x\r\nAccept: */*\r\nConnection: keep-alive\r\n\r\n"))
    assert st == 200


# ---------------------------------------------------------------- resilience

def test_connection_cap_503(srv):
    held = []
    try:
        # 64 idle connections that never finish a request
        for _ in range(64):
            c = socket.create_connection(("127.0.0.1", srv.http), timeout=10)
            c.sendall(b"GET /healthz HTTP/1.1\r\n")  # incomplete
            held.append(c)
        # all slots are occupied once the 65th is rejected; retry until the
        # server has accepted the earlier ones
        def rejected():
            st, h, body = get(srv, "/healthz")
            return (st, h, body) if st == 503 else None

        st, h, body = wait_for(rejected, "503 under cap")
        assert st == 503
        assert "application/json" in h["content-type"]
        json.loads(body)
    finally:
        for c in held:
            c.close()
    # slots free again
    wait_for(lambda: get(srv, "/healthz")[0] == 200, "recovery after releasing connections")


def test_udp_echo_correct_while_http_hammered(srv):
    stop = threading.Event()
    errors = []

    def hammer():
        while not stop.is_set():
            try:
                st, _, _ = get(srv, "/summary")
                if st not in (200, 503):
                    errors.append(st)
            except OSError:
                pass

    ts = [threading.Thread(target=hammer, daemon=True) for _ in range(8)]
    for t in ts:
        t.start()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_udp(srv.video, 2, range(200), sock=s)
        send_udp(srv.audio, 1, range(100, 150), sock=s)
    finally:
        stop.set()
        for t in ts:
            t.join(10)
    assert not errors
    assert get(srv, "/healthz")[0] == 200


def test_slow_partial_request_does_not_block_others(srv):
    c = socket.create_connection(("127.0.0.1", srv.http), timeout=10)
    try:
        c.sendall(b"GET /heal")
        assert get(srv, "/healthz")[0] == 200
    finally:
        c.close()


def test_summary_output_unchanged_on_stdout(srv):
    """The existing stdout format must still contain the original banner lines."""
    joined = "".join(srv.lines)
    assert "[server] TCP control listening on" in joined
    assert "[server] UDP audio reflector on" in joined
    assert "[server] UDP video reflector on" in joined
    assert "[server] HTTP API listening on 127.0.0.1:%d" % srv.http in joined
