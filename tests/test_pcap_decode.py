import os
import random
import struct
import tempfile
import unittest

from pcaplens import analyze, decode, pcap, synth

from .util import analysis_of, simple_exchange, write_with_linktype


class FormatTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.b = simple_exchange()
        self.expected = len(self.b.records)

    def path(self, name):
        return os.path.join(self.dir, name)

    def read(self, path):
        packets, info = pcap.open_capture(path)
        return list(packets), info

    def test_classic_variants(self):
        for name, kw in (("le.pcap", {}), ("be.pcap", {"big_endian": True}), ("ns.pcap", {"nano": True}),
                         ("bens.pcap", {"nano": True, "big_endian": True})):
            self.b.write_pcap(self.path(name), **kw)
            packets, info = self.read(self.path(name))
            self.assertEqual(len(packets), self.expected, name)
            self.assertEqual(info["warnings"], [], name)
            self.assertAlmostEqual(packets[0].ts, self.b.records[0][0], places=5, msg=name)
        self.assertIn("nanosecond", info["format"])

    def test_pcapng_little_and_big_endian_with_unknown_block(self):
        for name, kw in (("le.pcapng", {}), ("be.pcapng", {"big_endian": True}), ("nounk.pcapng", {"with_unknown_block": False})):
            self.b.write_pcapng(self.path(name), **kw)
            packets, info = self.read(self.path(name))
            self.assertEqual(len(packets), self.expected, name)
            self.assertEqual(info["format"], "pcapng")
            self.assertAlmostEqual(packets[0].ts, self.b.records[0][0], places=5, msg=name)

    def test_formats_decode_identically(self):
        a = analysis_of(self.b, self.dir, "pcap", "x1")
        c = analysis_of(self.b, self.dir, "pcapng", "x2")
        self.assertEqual((a.packets, len(a.flow_list), dict(a.protocols)), (c.packets, len(c.flow_list), dict(c.protocols)))

    def test_bad_inputs(self):
        for name, content in (("empty", b""), ("junk", b"hello world, not a capture"), ("short", b"\xd4\xc3\xb2\xa1\x02\x00")):
            with open(self.path(name), "wb") as fh:
                fh.write(content)
            with self.assertRaises(pcap.PcapError, msg=name):
                self.read(self.path(name))

    def test_truncated_capture_keeps_good_packets_and_warns(self):
        self.b.write_pcap(self.path("t.pcap"))
        with open(self.path("t.pcap"), "rb") as fh:
            data = fh.read()
        with open(self.path("cut.pcap"), "wb") as fh:
            fh.write(data[:-7])
        packets, info = self.read(self.path("cut.pcap"))
        self.assertEqual(len(packets), self.expected - 1)
        self.assertTrue(any("truncated" in w for w in info["warnings"]))

    def test_truncated_pcapng_warns(self):
        self.b.write_pcapng(self.path("t.pcapng"))
        with open(self.path("t.pcapng"), "rb") as fh:
            data = fh.read()
        with open(self.path("cut.pcapng"), "wb") as fh:
            fh.write(data[:-5])
        packets, info = self.read(self.path("cut.pcapng"))
        self.assertEqual(len(packets), self.expected - 1)
        self.assertTrue(info["warnings"])

    def test_implausible_record_length_stops_safely(self):
        with open(self.path("bad.pcap"), "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
            fh.write(struct.pack("<IIII", 1, 0, 0x7FFFFFFF, 10))
        packets, info = self.read(self.path("bad.pcap"))
        self.assertEqual(packets, [])
        self.assertTrue(any("implausible" in w for w in info["warnings"]))

    def test_empty_capture_is_fine(self):
        synth.Builder().write_pcap(self.path("e.pcap"))
        a = analyze.analyze_file(self.path("e.pcap"))
        self.assertEqual((a.packets, a.duration()), (0, 0.0))

    def test_other_linktypes(self):
        base = analysis_of(self.b, self.dir)
        for lt in (101, 113, 0):
            p = self.path("lt%d.pcap" % lt)
            write_with_linktype(self.b, p, lt)
            a = analyze.analyze_file(p)
            self.assertEqual(len(a.flow_list), len(base.flow_list), lt)
            self.assertEqual(a.packets, base.packets, lt)

    def test_unknown_linktype_is_not_fatal(self):
        with open(self.path("u.pcap"), "wb") as fh:
            fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 9999))
            fh.write(struct.pack("<IIII", 1, 0, 4, 4) + b"abcd")
        a = analyze.analyze_file(self.path("u.pcap"))
        self.assertEqual(a.packets, 1)
        self.assertIn("linktype-9999", a.protocols)


def pkt(data, linktype=1, index=0):
    return pcap.Packet(index, 1.0, linktype, data, len(data))


class DecodeTests(unittest.TestCase):
    def frames(self, fn):
        b = synth.Builder()
        fn(b)
        return [r[1] for r in b.records]

    def test_tcp_fields_and_flags(self):
        frame = self.frames(lambda b: b.tcp("192.168.1.2", 1234, "203.0.113.5", 80, synth.SYN | synth.ACK, 77, 88, b"data"))[0]
        d = decode.decode_packet(pkt(frame))
        self.assertEqual((d.src, d.dst, d.sport, d.dport, d.seq, d.ack, d.proto_name), ("192.168.1.2", "203.0.113.5", 1234, 80, 77, 88, "TCP"))
        self.assertEqual(d.flags, decode.SYN | decode.ACK)
        self.assertEqual(d.payload, b"data")

    def test_ethernet_padding_is_trimmed(self):
        frame = self.frames(lambda b: b.udp("192.168.1.2", 1000, "192.168.1.3", 2000, b"hi"))[0]
        d = decode.decode_packet(pkt(frame + b"\x00" * 20))
        self.assertEqual(d.payload, b"hi")

    def test_vlan_and_qinq(self):
        frame = self.frames(lambda b: b.udp("192.168.1.2", 1000, "192.168.1.3", 2000, b"hi"))[0]
        tagged = frame[:12] + struct.pack(">HH", 0x8100, 0x0064) + frame[12:]
        d = decode.decode_packet(pkt(tagged))
        self.assertEqual((d.vlan, d.dport), (100, 2000))
        qinq = frame[:12] + struct.pack(">HHHH", 0x88A8, 0x00C8, 0x8100, 0x0064) + frame[12:]
        self.assertEqual(decode.decode_packet(pkt(qinq)).dport, 2000)

    def test_ipv6(self):
        b = synth.Builder()
        b.tcp6("2001:db8::1", 4000, "2001:db8::2", 443, synth.SYN, 5)
        b.udp6("2001:db8::1", 5000, "2001:db8::2", 53, b"x")
        t, u = (decode.decode_packet(pkt(r[1])) for r in b.records)
        self.assertEqual((t.ip_version, t.src, t.dport, t.proto_name), (6, "2001:db8::1", 443, "TCP"))
        self.assertEqual((u.proto_name, u.dport), ("UDP", 53))

    def test_ipv6_extension_header_and_fragment(self):
        b = synth.Builder()
        seg = struct.pack(">HHHH", 1, 2, 8, 0)
        hop = struct.pack(">BB", 17, 0) + b"\x00" * 6
        frame = b.eth("0.0.0.1", "0.0.0.2", 0x86DD, b.ipv6("2001:db8::1", "2001:db8::2", 0, hop + seg))
        self.assertEqual(decode.decode_packet(pkt(frame)).proto_name, "UDP")
        frag = struct.pack(">BBHI", 17, 0, 0x0008, 1) + seg
        frame = b.eth("0.0.0.1", "0.0.0.2", 0x86DD, b.ipv6("2001:db8::1", "2001:db8::2", 44, frag))
        self.assertEqual(decode.decode_packet(pkt(frame)).proto_name, "IPv6-fragment")

    def test_ipv4_later_fragment_is_not_parsed_as_l4(self):
        b = synth.Builder()
        ip = b.ipv4("192.168.1.2", "192.168.1.3", 6, b"\x00" * 40, frag=0x0010)
        d = decode.decode_packet(pkt(b.eth("192.168.1.2", "192.168.1.3", 0x0800, ip)))
        self.assertEqual((d.fragment, d.proto_name, d.sport), (True, "IPv4-fragment", None))

    def test_icmp_and_arp(self):
        b = synth.Builder()
        b.icmp_echo("192.168.1.2", "203.0.113.9", b"x" * 40)
        b.arp(2, b"\x02\x00\x00\x00\x00\x01", "192.168.1.1", b"\x02\x00\x00\x00\x00\x02", "192.168.1.2")
        i, a = (decode.decode_packet(pkt(r[1])) for r in b.records)
        self.assertEqual((i.proto_name, i.icmp_type, len(i.payload)), ("ICMP", 8, 40))
        self.assertEqual((a.proto_name, a.arp["op"], a.arp["sender_ip"]), ("ARP", 2, "192.168.1.1"))

    def test_garbage_never_raises(self):
        rng = random.Random(7)
        base = self.frames(lambda b: (b.tcp("192.168.1.2", 1, "203.0.113.5", 80, 2, 1, 0, b"x" * 30),
                                      b.dns_query("192.168.1.2", "192.168.1.1", "a.example")))
        for lt in (1, 113, 0, 101, 228, 229, 12, 999):
            for _ in range(300):
                n = rng.randint(0, 120)
                data = bytes(rng.randrange(256) for _ in range(n))
                decode.decode_packet(pkt(data, lt))
            for frame in base:
                for cut in range(0, len(frame), 3):
                    decode.decode_packet(pkt(frame[:cut], lt))
                mutated = bytearray(frame)
                for _ in range(20):
                    mutated[rng.randrange(len(mutated))] = rng.randrange(256)
                    decode.decode_packet(pkt(bytes(mutated), lt))

    def test_truncated_headers_are_flagged_malformed(self):
        frame = self.frames(lambda b: b.tcp("192.168.1.2", 1, "203.0.113.5", 80, 2, 1))[0]
        self.assertTrue(decode.decode_packet(pkt(frame[:30])).malformed)
        self.assertTrue(decode.decode_packet(pkt(b"\x00" * 5)).malformed)


class DnsTests(unittest.TestCase):
    def query_bytes(self, name, qtype=1):
        return struct.pack(">HHHHHH", 7, 0x0100, 1, 0, 0, 0) + synth.dns_name(name) + struct.pack(">HH", qtype, 1)

    def test_question_and_types(self):
        m = decode.parse_dns(self.query_bytes("www.example.org", 16))
        self.assertEqual((m["qr"], m["questions"]), (False, [("www.example.org", "TXT")]))

    def test_response_with_compression_and_rdata(self):
        q = synth.dns_name("a.example")
        msg = struct.pack(">HHHHHH", 1, 0x8180, 1, 3, 0, 0) + q + struct.pack(">HH", 1, 1)
        msg += b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([203, 0, 113, 7])
        msg += b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 60, len(synth.dns_name("b.example"))) + synth.dns_name("b.example")
        txt = b"\x05hello\x05world"
        msg += b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, len(txt)) + txt
        m = decode.parse_dns(msg)
        self.assertEqual([x["data"] for x in m["answers"]], ["203.0.113.7", "b.example", "helloworld"])
        self.assertEqual(m["rcode"], "NOERROR")

    def test_nxdomain(self):
        msg = struct.pack(">HHHHHH", 1, 0x8183, 1, 0, 0, 0) + synth.dns_name("x.example") + struct.pack(">HH", 1, 1)
        self.assertEqual(decode.parse_dns(msg)["rcode"], "NXDOMAIN")

    def test_malformed_messages_return_none(self):
        loop = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack(">HH", 1, 1)  # pointer to itself
        for bad in (b"", b"\x00" * 5, loop, self.query_bytes("a.example")[:-6],
                    struct.pack(">HHHHHH", 1, 0, 9999, 0, 0, 0) + b"\x00" * 10):
            self.assertIsNone(decode.parse_dns(bad), bad[:10])

    def test_label_longer_than_message(self):
        bad = struct.pack(">HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x3f" + b"a" * 5
        self.assertIsNone(decode.parse_dns(bad))


class TlsTests(unittest.TestCase):
    def test_sni(self):
        self.assertEqual(decode.tls_sni(synth.tls_client_hello("secure.example")), "secure.example")

    def test_not_tls_or_truncated(self):
        hello = synth.tls_client_hello("secure.example")
        for data in (b"", b"GET / HTTP/1.1\r\n", hello[:10], hello[:60], b"\x16\x03\x01\x00\x05\x02"):
            self.assertIsNone(decode.tls_sni(data))


if __name__ == "__main__":
    unittest.main()
