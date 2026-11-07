import gzip
import tempfile
import unittest
import zlib
from unittest import mock

from pcaplens import analyze, http, synth

from .util import analysis_of

CLIENT, SERVER = "192.168.1.10", "203.0.113.10"
PAYLOAD_C2S = b"".join(b"request-part-%03d;" % i for i in range(300))
PAYLOAD_S2C = b"".join(b"response-chunk-%03d|" % i for i in range(300))


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def session(self, **kw):
        b = synth.Builder()
        b.tcp_session(CLIENT, 40000, SERVER, 80, PAYLOAD_C2S, PAYLOAD_S2C, **kw)
        a = analysis_of(b, self.dir)
        return a, a.flow_list[0]


class StreamTests(Base):
    def test_plain_reassembly_and_orientation(self):
        a, f = self.session()
        self.assertEqual(len(a.flow_list), 1)
        self.assertEqual((f.a, f.b), ((CLIENT, 40000), (SERVER, 80)))
        self.assertEqual(f.stream(0), (PAYLOAD_C2S, 0))
        self.assertEqual(f.stream(1), (PAYLOAD_S2C, 0))
        self.assertEqual((f.a2b_bytes, f.b2a_bytes), (len(PAYLOAD_C2S), len(PAYLOAD_S2C)))
        self.assertEqual(f.state, "closed")

    def test_out_of_order_segments(self):
        _, f = self.session(shuffle=True)
        self.assertEqual(f.stream(0)[0], PAYLOAD_C2S)
        self.assertEqual(f.stream(1)[0], PAYLOAD_S2C)

    def test_retransmissions_are_deduplicated(self):
        _, f = self.session(duplicate=True)
        self.assertEqual(f.stream(0)[0], PAYLOAD_C2S)
        self.assertEqual(f.stream(1)[0], PAYLOAD_S2C)

    def test_missing_segment_is_reported_as_gap(self):
        _, f = self.session(drop_segment=2, mss=900)
        data, gaps = f.stream(0)
        self.assertEqual(gaps, 1)
        self.assertEqual(len(data), len(PAYLOAD_C2S) - 900)
        self.assertTrue(data.startswith(PAYLOAD_C2S[:1800]))

    def test_sequence_number_wraparound(self):
        a, f = self.session(c_isn=0xFFFFFE00, s_isn=0xFFFFFF00)
        self.assertEqual(f.stream(0)[0], PAYLOAD_C2S)
        self.assertEqual(f.stream(1)[0], PAYLOAD_S2C)

    def test_capture_started_mid_connection(self):
        _, f = self.session(handshake=False)
        self.assertEqual(f.stream(0)[0], PAYLOAD_C2S)
        self.assertEqual(f.state, "midstream")

    def test_states(self):
        b = synth.Builder()
        b.tcp_session(CLIENT, 1, SERVER, 80, b"x", b"y", reset=True)
        b.syn_only(CLIENT, 2, SERVER, 81)
        b.tcp_session(CLIENT, 3, SERVER, 82, b"x", b"y")
        states = [f.state for f in analysis_of(b, self.dir).flow_list]
        self.assertEqual(states, ["reset", "attempt", "closed"])

    def test_syn_ack_first_flips_initiator(self):
        b = synth.Builder()
        b.tcp(SERVER, 80, CLIENT, 40000, synth.SYN | synth.ACK, 5000, 1001)
        f = analysis_of(b, self.dir).flow_list[0]
        self.assertEqual(f.a, (CLIENT, 40000))

    def test_stream_size_cap(self):
        with mock.patch.object(analyze, "MAX_STREAM_BYTES", 2000):
            _, f = self.session()
        self.assertTrue(all(f.truncated))
        self.assertLessEqual(len(f.stream(0)[0]), 2000)

    def test_udp_flow_and_counters(self):
        b = synth.Builder()
        b.udp(CLIENT, 5000, SERVER, 9999, b"hello")
        b.udp(SERVER, 9999, CLIENT, 5000, b"world!")
        b.icmp_echo(CLIENT, SERVER, b"p" * 32)
        a = analysis_of(b, self.dir)
        flow = a.flow_list[0]
        self.assertEqual((flow.proto, flow.packets, bytes(flow.udp)), ("UDP", 2, b"helloworld!"))
        self.assertEqual((a.packets, a.protocols["UDP"], a.protocols["ICMP"]), (3, 2, 1))
        self.assertEqual(len(a.icmp), 1)
        self.assertGreater(a.talkers[CLIENT], 0)

    def test_tls_sni_collected(self):
        b = synth.Builder()
        synth.tls_visit(b, "login.example")
        self.assertEqual(analysis_of(b, self.dir).flow_list[0].sni, "login.example")

    def test_is_internal(self):
        for ip in ("10.1.2.3", "192.168.0.9", "172.16.5.5", "127.0.0.1", "fe80::1", "169.254.1.1"):
            self.assertTrue(analyze.is_internal(ip), ip)
        for ip in ("203.0.113.5", "8.8.8.8", "2001:db8::1", "not-an-ip"):
            self.assertFalse(analyze.is_internal(ip), ip)


class HttpTests(unittest.TestCase):
    def req(self, extra=b"", body=b""):
        return b"POST /x HTTP/1.1\r\nHost: h.example\r\n" + extra + b"Content-Length: %d\r\n\r\n" % len(body) + body

    def test_requests_pipelined(self):
        data = b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\nUser-Agent: UA/1\r\n\r\n"
        msgs = http.parse_messages(data, False)
        self.assertEqual([m["target"] for m in msgs], ["/a", "/b"])
        self.assertEqual(msgs[1]["headers"]["user-agent"], "UA/1")

    def test_content_length_body_and_truncation(self):
        msgs = http.parse_messages(self.req(body=b"a=1&b=2"), False)
        self.assertEqual((msgs[0]["body"], msgs[0]["truncated"]), (b"a=1&b=2", False))
        cut = http.parse_messages(self.req(body=b"a=1&b=2")[:-3], False)
        self.assertTrue(cut[0]["truncated"])

    def test_response_variants(self):
        ok = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"
        self.assertEqual(http.parse_messages(ok, True)[0]["body"], b"hello")
        nc = http.parse_messages(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n", True)
        self.assertEqual(nc[0]["body"], b"")
        until_close = b"HTTP/1.0 200 OK\r\n\r\nbody until close"
        self.assertEqual(http.parse_messages(until_close, True)[0]["body"], b"body until close")

    def test_chunked(self):
        data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n"
        msgs = http.parse_messages(data, True)
        self.assertEqual(msgs[0]["body"], b"hello world")
        self.assertEqual([m["status"] for m in msgs], [200, 204])

    def test_incomplete_chunked_is_marked_truncated(self):
        data = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel"
        self.assertTrue(http.parse_messages(data, True)[0]["truncated"])

    def test_gzip_and_deflate(self):
        body = b"compressed text " * 50
        self.assertEqual(http.decompress(gzip.compress(body), "gzip"), (body, True))
        self.assertEqual(http.decompress(zlib.compress(body), "deflate"), (body, True))
        self.assertEqual(http.decompress(body, "identity"), (body, True))
        self.assertEqual(http.decompress(b"not gzip", "gzip")[1], False)

    def test_zip_bomb_is_capped(self):
        bomb = gzip.compress(b"\x00" * (5 * 1024 * 1024))
        out, ok = http.decompress(bomb, "gzip", limit=100000)
        self.assertEqual(len(out), 100000)
        self.assertFalse(ok)

    def test_garbage(self):
        for data in (b"", b"\x16\x03\x01 binary", b"GET", b"HTTP/1.1 abc\r\n\r\n", b"GET / HTTP/1.1\r\nHost: x\r\n"):
            self.assertEqual(http.parse_messages(data, False), [])
        self.assertFalse(http.looks_like_http(b"\x00\x01", False))
        self.assertTrue(http.looks_like_http(b"GET / HTTP/1.1\r\n", False))


if __name__ == "__main__":
    unittest.main()
