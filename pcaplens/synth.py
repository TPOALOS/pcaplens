"""Synthetic capture builder for demos and tests.

Everything here is made up: IPs come from private ranges (clients) and documentation ranges
(203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24), hosts end in .example, and credentials are fake.
No real traffic is captured or reproduced.
"""
import random
import socket
import struct

SYN, ACK, FIN, RST, PSH = 0x02, 0x10, 0x01, 0x04, 0x08


def ip_mac(ip, salt=0):
    parts = [int(x) for x in ip.split(".")] if "." in ip else [1, 2, 3, 4]
    return bytes([0x02, 0x00, salt & 0xFF] + parts[-3:])


def dns_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


class Builder:
    def __init__(self, start=1_700_000_000.0):
        self.records = []          # (ts, frame bytes)
        self.t = start
        self.ident = 1
        self.rng = random.Random(1234)

    # -- low level ------------------------------------------------------
    def advance(self, dt):
        self.t += dt

    def emit(self, frame, ts=None):
        self.records.append((self.t if ts is None else ts, frame))

    def eth(self, src_ip, dst_ip, ethertype, payload, smac=None, dmac=None):
        return (dmac or ip_mac(dst_ip, 1)) + (smac or ip_mac(src_ip, 2)) + struct.pack(">H", ethertype) + payload

    def ipv4(self, src, dst, proto, payload, ttl=64, frag=0x4000):
        self.ident += 1
        hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), self.ident & 0xFFFF, frag, ttl, proto, 0,
                          socket.inet_aton(src), socket.inet_aton(dst))
        return hdr + payload

    def tcp(self, src, sport, dst, dport, flags, seq, ack=0, payload=b"", ts=None):
        seg = struct.pack(">HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0)
        frame = self.eth(src, dst, 0x0800, self.ipv4(src, dst, 6, seg + payload))
        self.emit(frame, ts)

    def udp(self, src, sport, dst, dport, payload, ts=None):
        seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
        self.emit(self.eth(src, dst, 0x0800, self.ipv4(src, dst, 17, seg)), ts)

    def icmp_echo(self, src, dst, payload, reply=False, ts=None):
        msg = struct.pack(">BBHHH", 0 if reply else 8, 0, 0, 1, 1) + payload
        self.emit(self.eth(src, dst, 0x0800, self.ipv4(src, dst, 1, msg)), ts)

    def arp(self, op, smac, sip, tmac, tip, ts=None):
        body = struct.pack(">HHBBH", 1, 0x0800, 6, 4, op) + smac + socket.inet_aton(sip) + tmac + socket.inet_aton(tip)
        self.emit(self.eth(sip, tip, 0x0806, body, smac=smac, dmac=tmac if op == 2 else b"\xff" * 6), ts)

    def ipv6(self, src, dst, nh, payload, hop=64):
        return struct.pack(">IHBB", 6 << 28, len(payload), nh, hop) + socket.inet_pton(socket.AF_INET6, src) + socket.inet_pton(socket.AF_INET6, dst) + payload

    def tcp6(self, src, sport, dst, dport, flags, seq, ack=0, payload=b"", ts=None):
        seg = struct.pack(">HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0) + payload
        self.emit(self.eth("0.0.0.1", "0.0.0.2", 0x86DD, self.ipv6(src, dst, 6, seg)), ts)

    def udp6(self, src, sport, dst, dport, payload, ts=None):
        seg = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
        self.emit(self.eth("0.0.0.1", "0.0.0.2", 0x86DD, self.ipv6(src, dst, 17, seg)), ts)

    # -- TCP sessions ------------------------------------------------------
    def tcp_session(self, client, cport, server, sport, c2s=b"", s2c=b"", mss=900, c_isn=1000, s_isn=5000,
                    reset=False, shuffle=False, duplicate=False, drop_segment=None, gap=0.001, handshake=True):
        t = lambda: self.advance(gap)
        if handshake:
            self.tcp(client, cport, server, dport := sport, SYN, c_isn)
            t()
            self.tcp(server, sport, client, cport, SYN | ACK, s_isn, c_isn + 1)
            t()
            self.tcp(client, cport, server, dport, ACK, c_isn + 1, s_isn + 1)
            t()
        segs = []
        for off in range(0, len(c2s), mss):
            segs.append((client, cport, server, sport, c_isn + 1 + off, s_isn + 1, c2s[off:off + mss]))
        c_end = c_isn + 1 + len(c2s)
        for off in range(0, len(s2c), mss):
            segs.append((server, sport, client, cport, s_isn + 1 + off, c_end, s2c[off:off + mss]))
        order = list(range(len(segs)))
        if shuffle:
            self.rng.shuffle(order)
        for n, i in enumerate(order):
            if drop_segment is not None and i == drop_segment:
                continue
            src, sp, dst, dp, seq, ack, payload = segs[i]
            self.tcp(src, sp, dst, dp, PSH | ACK, seq, ack, payload)
            if duplicate:
                self.advance(gap / 2)
                self.tcp(src, sp, dst, dp, PSH | ACK, seq, ack, payload)
            t()
        if reset:
            self.tcp(server, sport, client, cport, RST | ACK, s_isn + 1 + len(s2c), c_end)
            t()
        elif handshake:
            s_end = s_isn + 1 + len(s2c)
            self.tcp(client, cport, server, sport, FIN | ACK, c_end, s_end)
            t()
            self.tcp(server, sport, client, cport, FIN | ACK, s_end, c_end + 1)
            t()
            self.tcp(client, cport, server, sport, ACK, c_end + 1, s_end + 1)
            t()

    def syn_only(self, src, sport, dst, dport, seq=1):
        self.tcp(src, sport, dst, dport, SYN, seq)

    # -- DNS ---------------------------------------------------------------
    def dns_query(self, client, resolver, name, qtype=1, sport=40000, ident=1):
        msg = struct.pack(">HHHHHH", ident, 0x0100, 1, 0, 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)
        self.udp(client, sport, resolver, 53, msg)

    def dns_response(self, client, resolver, name, answers=(), qtype=1, sport=40000, ident=1, rcode=0):
        """answers: list of (rtype, rdata bytes). Uses name compression (pointer to the question)."""
        msg = struct.pack(">HHHHHH", ident, 0x8180 | rcode, 1, len(answers), 0, 0) + dns_name(name) + struct.pack(">HH", qtype, 1)
        for rtype, rdata in answers:
            msg += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 300, len(rdata)) + rdata
        self.udp(resolver, 53, client, sport, msg)

    # -- output ---------------------------------------------------------------
    def write_pcap(self, path, nano=False, big_endian=False, linktype=1):
        end = ">" if big_endian else "<"
        magic = 0xA1B23C4D if nano else 0xA1B2C3D4
        with open(path, "wb") as fh:
            fh.write(struct.pack(end + "IHHiIII", magic, 2, 4, 0, 0, 65535, linktype))
            for ts, frame in sorted(self.records, key=lambda r: r[0]):
                sec = int(ts)
                frac = int(round((ts - sec) * (1e9 if nano else 1e6)))
                fh.write(struct.pack(end + "IIII", sec, frac, len(frame), len(frame)) + frame)

    def write_pcapng(self, path, big_endian=False, with_unknown_block=True):
        end = ">" if big_endian else "<"
        pad = lambda b: b + b"\x00" * (-len(b) % 4)

        def block(btype, body):
            body = pad(body)
            return struct.pack(end + "II", btype, len(body) + 12) + body + struct.pack(end + "I", len(body) + 12)

        bom = struct.pack(end + "I", 0x1A2B3C4D)
        out = block(0x0A0D0D0A, bom + struct.pack(end + "HHq", 1, 0, -1))
        opt_tsresol = struct.pack(end + "HH", 9, 1) + pad(bytes([6])) + struct.pack(end + "HH", 0, 0)  # microseconds
        out += block(1, struct.pack(end + "HHI", 1, 0, 65535) + opt_tsresol)
        if with_unknown_block:
            out += block(0x00000BAD, b"ignored")
        for ts, frame in sorted(self.records, key=lambda r: r[0]):
            ticks = int(round(ts * 1e6))
            out += block(6, struct.pack(end + "IIIII", 0, ticks >> 32, ticks & 0xFFFFFFFF, len(frame), len(frame)) + frame)
        with open(path, "wb") as fh:
            fh.write(out)


# ---- scenarios -------------------------------------------------------------------

CLIENT = "192.168.1.10"
RESOLVER = "192.168.1.1"
WEB = "203.0.113.10"
C2 = "198.51.100.66"
ATTACKER = "198.51.100.99"
SERVER = "192.168.1.20"


def http_get(b, host="www.example", path="/", ua="Mozilla/5.0 (synthetic)", cport=50000, server=WEB, body=b"<html>hello</html>",
             ctype="text/html", status="200 OK", extra_req=""):
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\n%s\r\n" % (path, host, ua, extra_req)).encode()
    resp = ("HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\n\r\n" % (status, ctype, len(body))).encode() + body
    b.tcp_session(CLIENT, cport, server, 80, req, resp)


def normal_browsing(b):
    http_get(b, path="/index.html", cport=50001)
    b.advance(0.5)
    http_get(b, path="/about.html", cport=50002, body=b"<html>about us</html>")


def port_scan(b, attacker=ATTACKER, target=SERVER, ports=range(1, 40)):
    for i, port in enumerate(ports):
        b.syn_only(attacker, 41000 + i, target, port)
        b.advance(0.01)


def beacon(b, interval=60.0, count=10, jitter=0.5, client=CLIENT, c2=C2):
    for i in range(count):
        b.advance(interval + b.rng.uniform(-jitter, jitter))
        b.tcp_session(client, 52000 + i, c2, 8443, b"ping", b"pong")


def dns_tunnel(b, domain="t.tunnel.example", count=30, client=CLIENT):
    for i in range(count):
        label = "".join(b.rng.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(40))  # secretscan:ignore
        b.dns_query(client, RESOLVER, "%s.%s" % (label, domain), qtype=16, sport=30000 + i, ident=i)
        b.advance(0.05)
        b.dns_response(client, RESOLVER, "%s.%s" % (label, domain), [], qtype=16, sport=30000 + i, ident=i, rcode=3)
        b.advance(0.05)


def nxdomain_storm(b, count=25, client=CLIENT):
    for i in range(count):
        name = "host%03d-%s.example" % (i, "".join(b.rng.choice("bcdfghjk") for _ in range(8)))
        b.dns_query(client, RESOLVER, name, sport=31000 + i, ident=i)
        b.dns_response(client, RESOLVER, name, [], sport=31000 + i, ident=i, rcode=3)
        b.advance(0.02)


def cleartext_http_login(b, cport=50100):
    body = b"username=alice&password=fake-demo-pass-1"
    req = (b"POST /login HTTP/1.1\r\nHost: portal.example\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: %d\r\n\r\n" % len(body)) + body
    b.tcp_session(CLIENT, cport, WEB, 80, req, b"HTTP/1.1 302 Found\r\nLocation: /home\r\nContent-Length: 0\r\n\r\n")


def http_basic_auth(b, cport=50101):
    import base64
    cred = base64.b64encode(b"bob:fake-basic-pass-2").decode()
    http_get(b, host="intranet.example", path="/admin", cport=cport, extra_req="Authorization: Basic %s\r\n" % cred)


def ftp_login(b, cport=50102):
    ftp_server = "198.51.100.30"
    b.tcp_session(CLIENT, cport, ftp_server, 21, b"USER carol\r\nPASS fake-ftp-pass-3\r\nQUIT\r\n",
                  b"220 FTP ready\r\n331 Password required\r\n230 Logged in\r\n221 Bye\r\n")


def arp_spoof(b, gateway="192.168.1.1"):
    good, evil = ip_mac(gateway, 5), b"\x02\xee\xee\xee\xee\xee"
    b.arp(2, good, gateway, ip_mac(CLIENT, 2), CLIENT)
    b.advance(1)
    b.arp(2, evil, gateway, ip_mac(CLIENT, 2), CLIENT)


def icmp_tunnel(b, count=15, src=CLIENT, dst=C2):
    for i in range(count):
        b.icmp_echo(src, dst, bytes(range(256))[:200])
        b.advance(0.2)


def exe_download(b, cport=50200):
    http_get(b, host="files.example", path="/update.exe", cport=cport, body=b"MZ" + b"\x90" * 200, ctype="application/octet-stream")


def scanner_and_attack_requests(b, cport=50300):
    http_get(b, host="shop.example", path="/index.php?id=1%27%20OR%20%271%27=%271", cport=cport, server=SERVER,
             ua="sqlmap/1.7 (synthetic)")
    http_get(b, host="shop.example", path="/download?file=../../etc/passwd", cport=cport + 1, server=SERVER)


def large_upload(b, size=300_000, cport=50400):
    b.tcp_session(CLIENT, cport, C2, 443, b"X" * size, b"ok", mss=1400)


def tls_client_hello(sni):
    name = sni.encode()
    server_name = struct.pack(">HBH", len(name) + 3, 0, len(name)) + name
    ext = struct.pack(">HH", 0, len(server_name)) + server_name
    body = (b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00"
            + struct.pack(">H", len(ext)) + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def tls_visit(b, sni="secure.example", cport=50500):
    b.tcp_session(CLIENT, cport, WEB, 443, tls_client_hello(sni), b"\x16\x03\x03\x00\x04junk")


def ctf_flags(b, cport=50600):
    """Fake CTF-style flags: one in plain text, one base64-encoded, one inside a DNS name."""
    import base64
    plain = b"<html>nothing to see... flag{synthetic_plain_demo}</html>"
    hidden = base64.b64encode(b"flag{synthetic_base64_demo}")
    http_get(b, host="ctf.example", path="/notes", cport=cport, body=plain + b"\n<!-- " + hidden + b" -->")
    b.dns_query(CLIENT, RESOLVER, "flag{synthetic_dns_demo}.ctf.example", sport=32000)


def demo_capture(b=None):
    """A capture that shows every detector firing at least once."""
    b = b or Builder()
    normal_browsing(b)
    ctf_flags(b)
    tls_visit(b)
    http_basic_auth(b)
    cleartext_http_login(b)
    ftp_login(b)
    exe_download(b)
    scanner_and_attack_requests(b)
    port_scan(b)
    arp_spoof(b)
    icmp_tunnel(b)
    dns_tunnel(b)
    nxdomain_storm(b)
    large_upload(b)
    beacon(b)
    return b
