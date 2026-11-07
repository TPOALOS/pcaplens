"""Readers for classic pcap and pcapng capture files (pure Python, streaming)."""
import struct

MAX_PACKET = 16 * 1024 * 1024


class PcapError(ValueError):
    """The file is not a readable capture."""


class Packet:
    __slots__ = ("index", "ts", "linktype", "data", "orig_len")

    def __init__(self, index, ts, linktype, data, orig_len):
        self.index, self.ts, self.linktype, self.data, self.orig_len = index, ts, linktype, data, orig_len


def read_exact(fh, n):
    buf = fh.read(n)
    return buf if len(buf) == n else None


def open_capture(path):
    """Return (iterator of Packet, info dict). info['warnings'] fills while iterating."""
    fh = open(path, "rb")
    magic = fh.read(4)
    info = {"format": None, "warnings": []}
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return _classic(fh, magic, info), info
    if magic == b"\x0a\x0d\x0d\x0a":
        return _pcapng(fh, info), info
    fh.close()
    raise PcapError("not a pcap or pcapng file (unknown magic %r)" % magic)


def _classic(fh, magic, info):
    little = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    end = "<" if little else ">"
    info["format"] = "pcap" + (" (nanosecond)" if nano else "")
    rest = read_exact(fh, 20)
    if rest is None:
        fh.close()
        raise PcapError("truncated pcap header")
    _major, _minor, _zone, _sig, snaplen, linktype = struct.unpack(end + "HHiIII", rest)
    info["linktype"] = linktype
    info["snaplen"] = snaplen
    scale = 1e-9 if nano else 1e-6

    def gen():
        index = 0
        try:
            while True:
                hdr = fh.read(16)
                if not hdr:
                    return
                if len(hdr) < 16:
                    info["warnings"].append("truncated record header at end of file")
                    return
                sec, frac, incl, orig = struct.unpack(end + "IIII", hdr)
                if incl > MAX_PACKET:
                    info["warnings"].append("record %d has an implausible length (%d); stopping" % (index, incl))
                    return
                data = fh.read(incl)
                if len(data) < incl:
                    info["warnings"].append("truncated packet %d at end of file" % index)
                    return
                yield Packet(index, sec + frac * scale, linktype, data, orig)
                index += 1
        finally:
            fh.close()
    return gen()


def _options(buf, end):
    out, off = {}, 0
    while off + 4 <= len(buf):
        code, length = struct.unpack(end + "HH", buf[off:off + 4])
        if code == 0:
            break
        out[code] = buf[off + 4:off + 4 + length]
        off += 4 + ((length + 3) & ~3)
    return out


def _pcapng(fh, info):
    info["format"] = "pcapng"

    def gen():
        end, ifaces, index = "<", [], 0
        first = True
        try:
            while True:
                head = b"\x0a\x0d\x0d\x0a" if first else fh.read(4)
                first = False
                if not head:
                    return
                if len(head) < 4:
                    info["warnings"].append("truncated block header at end of file")
                    return
                raw_len = fh.read(4)
                if len(raw_len) < 4:
                    info["warnings"].append("truncated block at end of file")
                    return
                if head == b"\x0a\x0d\x0d\x0a":  # section header: byte order decided by its magic
                    bom = fh.read(4)
                    if bom == b"\x4d\x3c\x2b\x1a":
                        end = "<"
                    elif bom == b"\x1a\x2b\x3c\x4d":
                        end = ">"
                    else:
                        raise PcapError("invalid pcapng byte-order magic")
                    (total,) = struct.unpack(end + "I", raw_len)
                    rest = fh.read(total - 12) if total >= 28 else b""
                    if total < 28 or len(rest) < total - 12:
                        info["warnings"].append("truncated or invalid section header")
                        return
                    ifaces = []
                    continue
                btype = struct.unpack(end + "I", head)[0]
                (total,) = struct.unpack(end + "I", raw_len)
                if total < 12 or total > MAX_PACKET + 64:
                    info["warnings"].append("invalid pcapng block length %d; stopping" % total)
                    return
                body = fh.read(total - 12)
                trailer = fh.read(4)
                if len(body) < total - 12 or len(trailer) < 4:
                    info["warnings"].append("truncated block at end of file")
                    return
                if btype == 1 and len(body) >= 8:  # interface description
                    linktype, _res, snap = struct.unpack(end + "HHI", body[:8])
                    opts = _options(body[8:], end)
                    scale = 1e-6
                    if 9 in opts and opts[9]:
                        v = opts[9][0]
                        scale = (2.0 ** -(v & 0x7F)) if v & 0x80 else (10.0 ** -v)
                    ifaces.append((linktype, scale))
                    info.setdefault("linktype", linktype)
                elif btype == 6 and len(body) >= 20:  # enhanced packet
                    iface, hi, lo, cap, orig = struct.unpack(end + "IIIII", body[:20])
                    if iface >= len(ifaces) or 20 + cap > len(body):
                        info["warnings"].append("packet block %d is malformed" % index)
                        continue
                    linktype, scale = ifaces[iface]
                    yield Packet(index, ((hi << 32) | lo) * scale, linktype, body[20:20 + cap], orig)
                    index += 1
                elif btype == 3 and ifaces and len(body) >= 4:  # simple packet (no timestamp)
                    (orig,) = struct.unpack(end + "I", body[:4])
                    yield Packet(index, 0.0, ifaces[0][0], body[4:4 + min(orig, len(body) - 4)], orig)
                    index += 1
        finally:
            fh.close()
    return gen()
