"""One pass over a capture: counters, flows, TCP stream reassembly, DNS/ARP/ICMP/SYN event lists."""
import collections
import ipaddress

from . import decode, pcap

MAX_STREAM_BYTES = 8 * 1024 * 1024
MAX_UDP_BYTES = 1024 * 1024
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
    "fc00::/7", "fe80::/10", "::1/128")]


def is_internal(ip, nets=INTERNAL_NETS):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets if n.version == addr.version)


class Flow:
    def __init__(self, fid, proto, a, b, ts):
        self.id, self.proto, self.a, self.b = fid, proto, a, b      # a = initiator (ip, port), b = responder
        self.packets = self.bytes = 0
        self.a2b_bytes = self.b2a_bytes = 0                          # payload bytes per direction
        self.first_ts = self.last_ts = ts
        self.syn = self.synack = self.fin = self.rst = 0
        self.segs = ({}, {})                                         # direction -> {seq: payload} (first wins)
        self.stored = [0, 0]
        self.isn = [None, None]
        self.truncated = [False, False]
        self.udp = bytearray()
        self.sni = None
        self._cache = {}

    @property
    def state(self):
        if self.proto != "TCP":
            return "-"
        if self.rst:
            return "reset"
        if self.synack:
            return "closed" if self.fin else "established"
        return "attempt" if self.syn else "midstream"

    def add_segment(self, direction, seq, payload, is_syn):
        if is_syn:
            self.isn[direction] = seq
        if not payload:
            return
        if self.stored[direction] + len(payload) > MAX_STREAM_BYTES:
            self.truncated[direction] = True
            return
        if seq not in self.segs[direction]:
            self.segs[direction][seq] = payload
            self.stored[direction] += len(payload)

    def stream(self, direction):
        """Reassembled bytes of one direction and the number of gaps (cached)."""
        if direction in self._cache:
            return self._cache[direction]
        segs = self.segs[direction]
        out, gaps = bytearray(), 0
        if segs:
            base = (self.isn[direction] + 1) & 0xFFFFFFFF if self.isn[direction] is not None else min(segs)
            items = sorted(((seq - base) & 0xFFFFFFFF, p) for seq, p in segs.items())
            items = [(o, p) for o, p in items if o < 0x80000000]      # drop segments before the base
            pos = 0
            for off, payload in items:
                if off > pos:
                    gaps += 1
                    pos = off
                if off + len(payload) > pos:
                    out += payload[pos - off:]
                    pos = off + len(payload)
        self._cache[direction] = (bytes(out), gaps)
        return self._cache[direction]

    def to_dict(self):
        return {"id": self.id, "proto": self.proto, "src": "%s:%s" % self.a, "dst": "%s:%s" % self.b,
                "packets": self.packets, "bytes": self.bytes, "bytes_out": self.a2b_bytes, "bytes_in": self.b2a_bytes,
                "start": self.first_ts, "end": self.last_ts, "state": self.state}


class Analysis:
    def __init__(self, path=None):
        self.path = path
        self.info = {}
        self.packets = self.bytes = self.malformed = 0
        self.first_ts = self.last_ts = None
        self.protocols = collections.Counter()
        self.talkers = collections.Counter()
        self.flows = {}
        self.flow_list = []
        self.dns = []        # (ts, src, dst, message)
        self.arp = []        # (ts, dict)
        self.icmp = []       # (ts, src, dst, type, code, payload_len)
        self.syns = []       # (ts, src, dst, dport)
        self.synacks = []    # (ts, server, client, sport)
        self.finalized = False

    # -- feeding -------------------------------------------------------
    def add(self, d):
        self.packets += 1
        self.bytes += d.length
        if d.ts:
            self.first_ts = d.ts if self.first_ts is None else min(self.first_ts, d.ts)
            self.last_ts = d.ts if self.last_ts is None else max(self.last_ts, d.ts)
        if d.malformed:
            self.malformed += 1
        self.protocols[d.proto_name or ("IPv%d" % d.ip_version if d.ip_version else "other")] += 1
        if d.src:
            self.talkers[d.src] += d.length
        if d.arp:
            self.arp.append((d.ts, d.arp))
        if d.proto_name in ("ICMP", "ICMPv6") and d.src:
            self.icmp.append((d.ts, d.src, d.dst, d.icmp_type, d.icmp_code, len(d.payload or b"")))
        if d.dns:
            self.dns.append((d.ts, d.src, d.dst, d.dns))
        if d.proto_name in ("TCP", "UDP") and d.src and d.sport is not None:
            self._flow(d)

    def _flow(self, d):
        ep_s, ep_d = (d.src, d.sport), (d.dst, d.dport)
        key = (d.proto_name,) + tuple(sorted([ep_s, ep_d]))
        flow = self.flows.get(key)
        if flow is None:
            a, b = ep_s, ep_d
            if d.proto_name == "TCP" and d.flags & decode.SYN and d.flags & decode.ACK:
                a, b = ep_d, ep_s                      # we missed the SYN: the receiver was the initiator
            flow = Flow(len(self.flow_list), d.proto_name, a, b, d.ts)
            self.flows[key] = flow
            self.flow_list.append(flow)
        direction = 0 if ep_s == flow.a else 1
        flow.packets += 1
        flow.bytes += d.length
        flow.last_ts = max(flow.last_ts, d.ts)
        n = len(d.payload or b"")
        if direction == 0:
            flow.a2b_bytes += n
        else:
            flow.b2a_bytes += n
        if d.proto_name == "UDP":
            if n and len(flow.udp) < MAX_UDP_BYTES:
                flow.udp += d.payload[:MAX_UDP_BYTES - len(flow.udp)]
            return
        syn, ack = bool(d.flags & decode.SYN), bool(d.flags & decode.ACK)
        if syn and not ack:
            flow.syn += 1
            self.syns.append((d.ts, d.src, d.dst, d.dport))
        elif syn and ack:
            flow.synack += 1
            self.synacks.append((d.ts, d.src, d.dst, d.sport))
        if d.flags & decode.FIN:
            flow.fin += 1
        if d.flags & decode.RST:
            flow.rst += 1
        flow.add_segment(direction, d.seq, d.payload, syn)

    # -- finishing -----------------------------------------------------
    def finalize(self):
        if self.finalized:
            return self
        for flow in self.flow_list:
            if flow.proto == "TCP" and flow.segs[0]:
                data, _ = flow.stream(0)
                flow.sni = decode.tls_sni(data[:4096])
        self.finalized = True
        return self

    def duration(self):
        return (self.last_ts - self.first_ts) if self.first_ts is not None and self.last_ts else 0.0


def analyze_file(path, progress=None):
    """Read `path` and return a finalized Analysis."""
    packets, info = pcap.open_capture(path)
    result = Analysis(path)
    for pkt in packets:
        result.add(decode.decode_packet(pkt))
        if progress and pkt.index % 100000 == 0:
            progress(pkt.index)
    result.info = info
    return result.finalize()
