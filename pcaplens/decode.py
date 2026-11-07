"""Packet decoding: Ethernet/VLAN/SLL/loopback, IPv4/IPv6, TCP/UDP/ICMP/ARP, DNS, TLS SNI.

Every parser is bounds-checked: malformed input yields None or a partial result, never an exception
escaping to the caller.
"""
import ipaddress
import socket
import struct

FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20
DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
             33: "SRV", 10: "NULL", 255: "ANY", 65: "HTTPS"}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class Decoded:
    """Result of decoding one packet. Unset layers stay None."""
    __slots__ = ("index", "ts", "length", "src_mac", "dst_mac", "vlan", "ethertype", "ip_version", "src", "dst",
                 "ttl", "proto", "fragment", "proto_name", "sport", "dport", "flags", "seq", "ack", "payload",
                 "icmp_type", "icmp_code", "arp", "dns", "malformed")

    def __init__(self, index, ts, length):
        self.index, self.ts, self.length = index, ts, length
        for name in self.__slots__[3:]:
            setattr(self, name, None)
        self.malformed = False


def mac(raw):
    return ":".join("%02x" % b for b in raw)


def decode_packet(pkt):
    d = Decoded(pkt.index, pkt.ts, pkt.orig_len or len(pkt.data))
    try:
        _link(d, pkt.linktype, pkt.data)
    except (struct.error, IndexError, ValueError):
        d.malformed = True
    return d


def _link(d, linktype, data):
    if linktype == 1:                       # Ethernet
        if len(data) < 14:
            d.malformed = True
            return
        d.dst_mac, d.src_mac = mac(data[0:6]), mac(data[6:12])
        etype, off = struct.unpack(">H", data[12:14])[0], 14
        while etype in (0x8100, 0x88A8) and len(data) >= off + 4:  # VLAN tags (incl. QinQ)
            d.vlan = struct.unpack(">H", data[off:off + 2])[0] & 0x0FFF
            etype = struct.unpack(">H", data[off + 2:off + 4])[0]
            off += 4
        _network(d, etype, data[off:])
    elif linktype == 113:                   # Linux cooked capture
        if len(data) < 16:
            d.malformed = True
            return
        _network(d, struct.unpack(">H", data[14:16])[0], data[16:])
    elif linktype == 0:                     # BSD loopback / null
        if len(data) < 4:
            d.malformed = True
            return
        fam = struct.unpack("<I", data[:4])[0]
        if fam > 0xFFFF:
            fam = struct.unpack(">I", data[:4])[0]
        _network(d, 0x0800 if fam == 2 else 0x86DD, data[4:])
    elif linktype in (101, 12, 228, 229):   # raw IP
        if data:
            _network(d, 0x0800 if data[0] >> 4 == 4 else 0x86DD, data)
    else:
        d.proto_name = "linktype-%d" % linktype


def _network(d, etype, data):
    d.ethertype = etype
    if etype == 0x0800:
        _ipv4(d, data)
    elif etype == 0x86DD:
        _ipv6(d, data)
    elif etype == 0x0806:
        _arp(d, data)
    else:
        d.proto_name = "ethertype-0x%04x" % etype


def _arp(d, data):
    if len(data) < 28:
        d.malformed = True
        return
    op = struct.unpack(">H", data[6:8])[0]
    d.proto_name = "ARP"
    d.arp = {"op": op, "sender_mac": mac(data[8:14]), "sender_ip": socket.inet_ntoa(data[14:18]),
             "target_mac": mac(data[18:24]), "target_ip": socket.inet_ntoa(data[24:28])}
    d.src, d.dst = d.arp["sender_ip"], d.arp["target_ip"]


def _ipv4(d, data):
    if len(data) < 20 or data[0] >> 4 != 4:
        d.malformed = True
        return
    ihl = (data[0] & 0x0F) * 4
    total = struct.unpack(">H", data[2:4])[0]
    if ihl < 20 or len(data) < ihl:
        d.malformed = True
        return
    flags_frag = struct.unpack(">H", data[6:8])[0]
    d.ip_version, d.ttl, d.proto = 4, data[8], data[9]
    d.src, d.dst = socket.inet_ntoa(data[12:16]), socket.inet_ntoa(data[16:20])
    payload = data[ihl:total] if ihl <= total <= len(data) else data[ihl:]  # trim Ethernet padding
    if (flags_frag & 0x1FFF) or (flags_frag & 0x2000):  # fragment: do not parse L4 of later pieces
        d.fragment = True
        if flags_frag & 0x1FFF:
            d.proto_name = "IPv4-fragment"
            return
    _transport(d, d.proto, payload)


def _ipv6(d, data):
    if len(data) < 40 or data[0] >> 4 != 6:
        d.malformed = True
        return
    plen, nh, hop = struct.unpack(">HBB", data[4:8])
    d.ip_version, d.ttl = 6, hop
    d.src, d.dst = str(ipaddress.IPv6Address(data[8:24])), str(ipaddress.IPv6Address(data[24:40]))
    payload = data[40:40 + plen] if plen else data[40:]
    for _ in range(8):                       # walk extension headers
        if nh in (0, 43, 60) and len(payload) >= 8:
            nh, ln = payload[0], (payload[1] + 1) * 8
            payload = payload[ln:]
        elif nh == 44 and len(payload) >= 8:  # fragment header
            nh = payload[0]
            if struct.unpack(">H", payload[2:4])[0] & 0xFFF8:
                d.fragment, d.proto_name = True, "IPv6-fragment"
                return
            payload = payload[8:]
        elif nh == 51 and len(payload) >= 8:  # authentication header
            nh, ln = payload[0], (payload[1] + 2) * 4
            payload = payload[ln:]
        else:
            break
    d.proto = nh
    _transport(d, nh, payload)


def _transport(d, proto, data):
    if proto == 6:
        if len(data) < 20:
            d.malformed = True
            return
        sport, dport, seq, ack, off_flags = struct.unpack(">HHIIH", data[:14])
        off = (off_flags >> 12) * 4
        if off < 20 or off > len(data):
            d.malformed = True
            return
        d.proto_name, d.sport, d.dport, d.seq, d.ack = "TCP", sport, dport, seq, ack
        d.flags, d.payload = off_flags & 0x3F, data[off:]
        if 53 in (sport, dport) and len(d.payload) > 2:       # DNS over TCP: 2-byte length prefix
            d.dns = parse_dns(d.payload[2:])
    elif proto == 17:
        if len(data) < 8:
            d.malformed = True
            return
        sport, dport, ulen = struct.unpack(">HHH", data[:6])
        d.proto_name, d.sport, d.dport = "UDP", sport, dport
        d.payload = data[8:ulen] if 8 <= ulen <= len(data) else data[8:]
        if 53 in (sport, dport) or 5353 in (sport, dport):
            d.dns = parse_dns(d.payload)
    elif proto in (1, 58):
        if len(data) < 4:
            d.malformed = True
            return
        d.proto_name = "ICMP" if proto == 1 else "ICMPv6"
        d.icmp_type, d.icmp_code, d.payload = data[0], data[1], data[8:] if len(data) > 8 else b""
    else:
        d.proto_name = "IP-proto-%d" % proto


# ---- DNS ---------------------------------------------------------------

def _read_name(msg, off):
    """Decode a (possibly compressed) DNS name. Returns (name, offset after the name in place)."""
    labels, jumps, end = [], 0, None
    while True:
        if off >= len(msg):
            raise ValueError("name runs past message")
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:
            if off + 1 >= len(msg):
                raise ValueError("bad pointer")
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if end is None:
                end = off + 2
            jumps += 1
            if jumps > 20 or ptr >= len(msg):
                raise ValueError("compression loop")
            off = ptr
            continue
        if ln > 63 or off + 1 + ln > len(msg):
            raise ValueError("bad label")
        labels.append(msg[off + 1:off + 1 + ln].decode("ascii", errors="replace"))
        off += 1 + ln
        if len(labels) > 127:
            raise ValueError("name too long")
    return ".".join(labels), (end if end is not None else off)


def _rdata(msg, rtype, off, ln):
    raw = msg[off:off + ln]
    try:
        if rtype == 1 and ln == 4:
            return socket.inet_ntoa(raw)
        if rtype == 28 and ln == 16:
            return str(ipaddress.IPv6Address(raw))
        if rtype in (2, 5, 12):
            return _read_name(msg, off)[0]
        if rtype == 15 and ln >= 3:
            return "%d %s" % (struct.unpack(">H", raw[:2])[0], _read_name(msg, off + 2)[0])
        if rtype == 16:
            parts, i = [], 0
            while i < len(raw):
                n = raw[i]
                parts.append(raw[i + 1:i + 1 + n].decode("utf-8", errors="replace"))
                i += 1 + n
            return "".join(parts)
    except ValueError:
        pass
    return raw.hex()


def parse_dns(msg):
    """Return {'id','qr','rcode','questions':[(name,type)],'answers':[{...}]} or None when malformed."""
    try:
        if len(msg) < 12:
            return None
        ident, flags, qd, an, _ns, _ar = struct.unpack(">HHHHHH", msg[:12])
        if qd > 32 or an > 128:
            return None
        off, questions, answers = 12, [], []
        for _ in range(qd):
            name, off = _read_name(msg, off)
            qtype, _qclass = struct.unpack(">HH", msg[off:off + 4])
            off += 4
            questions.append((name, DNS_TYPES.get(qtype, str(qtype))))
        for _ in range(an):
            name, off = _read_name(msg, off)
            rtype, _cls, ttl, rdlen = struct.unpack(">HHIH", msg[off:off + 10])
            off += 10
            if off + rdlen > len(msg):
                break
            answers.append({"name": name, "type": DNS_TYPES.get(rtype, str(rtype)), "ttl": ttl,
                            "data": _rdata(msg, rtype, off, rdlen)})
            off += rdlen
        return {"id": ident, "qr": bool(flags & 0x8000), "rcode": RCODES.get(flags & 0xF, str(flags & 0xF)),
                "questions": questions, "answers": answers}
    except (ValueError, struct.error, IndexError):
        return None


# ---- TLS ---------------------------------------------------------------

def tls_sni(data):
    """Server name from a TLS ClientHello at the start of `data`, or None."""
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None
        pos = 5 + 4 + 2 + 32                     # record hdr, handshake hdr, version, random
        pos += 1 + data[pos]                     # session id
        pos += 2 + struct.unpack(">H", data[pos:pos + 2])[0]   # cipher suites
        pos += 1 + data[pos]                     # compression
        ext_len = struct.unpack(">H", data[pos:pos + 2])[0]
        pos += 2
        end = min(len(data), pos + ext_len)
        while pos + 4 <= end:
            etype, elen = struct.unpack(">HH", data[pos:pos + 4])
            pos += 4
            if etype == 0 and elen >= 5:         # server_name
                nlen = struct.unpack(">H", data[pos + 3:pos + 5])[0]
                return data[pos + 5:pos + 5 + nlen].decode("ascii", errors="replace")
            pos += elen
    except (IndexError, struct.error):
        return None
    return None
