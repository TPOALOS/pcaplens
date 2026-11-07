"""Detectors: turn an Analysis into findings (rule, severity, evidence)."""
import base64
import binascii
import collections
import math
import re
import statistics
import urllib.parse

from . import http
from .analyze import is_internal

SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SECOND_LEVEL = {"co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "com.br", "com.tr", "co.jp", "co.in", "co.za"}
PASS_KEYS = ("password", "passwd", "pwd", "pass", "passphrase", "secret", "api_key", "apikey", "access_token")
USER_KEYS = ("username", "user", "login", "email", "userid", "uname")
SCANNER_UAS = ("sqlmap", "nikto", "nmap", "masscan", "zgrab", "gobuster", "dirbuster", "hydra", "wpscan", "acunetix", "nessus")
ATTACK_PATTERNS = [
    ("path traversal", re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.I)),
    ("SQL injection", re.compile(r"(union\s+(all\s+)?select|'\s*or\s*'?\d'?\s*=\s*'?\d|sleep\s*\(\s*\d|information_schema|;\s*drop\s+table)", re.I)),
    ("cross-site scripting", re.compile(r"(<\s*script|javascript:|onerror\s*=)", re.I)),
    ("command injection", re.compile(r"(;|\|\||&&)\s*(cat|wget|curl|nc|bash|sh)\s", re.I)),
    ("sensitive file access", re.compile(r"(/etc/passwd|/etc/shadow|win\.ini|\.git/config|\.env\b)", re.I)),
    ("log4shell probe", re.compile(r"\$\{jndi:", re.I)),
]


class Thresholds:
    scan_ports = 15
    scan_hosts = 10
    synflood_count = 300
    beacon_min = 6
    beacon_min_interval = 1.0
    beacon_cv = 0.25
    beacon_external_only = True
    dns_min_unique = 20
    dns_avglen = 25
    dns_entropy = 3.5
    nx_min = 20
    icmp_count = 10
    icmp_payload = 100
    exfil_bytes = 5 * 1024 * 1024
    exfil_ratio = 10

    def __init__(self, **overrides):
        for k, v in overrides.items():
            if not hasattr(Thresholds, k):
                raise KeyError("unknown threshold %r" % k)
            setattr(self, k, v)


class Finding:
    def __init__(self, severity, rule, title, detail, evidence=None, ts=None):
        self.severity, self.rule, self.title, self.detail = severity, rule, title, detail
        self.evidence, self.ts = evidence or {}, ts

    def to_dict(self):
        return {"severity": self.severity, "rule": self.rule, "title": self.title, "detail": self.detail,
                "evidence": self.evidence, "time": self.ts}


def entropy(text):
    if not text:
        return 0.0
    counts = collections.Counter(text)
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def registered_domain(name):
    labels = name.lower().rstrip(".").split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in SECOND_LEVEL:
        return ".".join(labels[-3:]), labels[:-3]
    return ".".join(labels[-2:]), labels[:-2]


def mask(value):
    return "*" * min(max(len(value), 4), 12)


# ---- network-level ---------------------------------------------------------------

def probes(a):
    """TCP connection attempts that never carried data: SYN scans, connect() scans and sweeps."""
    return [f for f in a.flow_list if f.proto == "TCP" and f.syn and f.a2b_bytes == 0 and f.b2a_bytes == 0]


def port_scan(a, th):
    by_src = collections.defaultdict(list)
    for f in probes(a):
        by_src[f.a[0]].append(f)
    out = []
    for src, flows in by_src.items():
        by_dst, by_port = collections.defaultdict(dict), collections.defaultdict(set)
        for f in flows:
            by_dst[f.b[0]][f.b[1]] = by_dst[f.b[0]].get(f.b[1], False) or bool(f.synack)
            by_port[f.b[1]].add(f.b[0])
        first = min(f.first_ts for f in flows)
        for dst, ports in by_dst.items():
            if len(ports) >= th.scan_ports:
                open_ports = sorted(p for p, ok in ports.items() if ok)
                out.append(Finding("HIGH" if len(ports) >= 100 else "MEDIUM", "port-scan",
                                   "Port scan: %s probed %d ports on %s" % (src, len(ports), dst),
                                   "%d distinct TCP ports received connection attempts without any data; %d answered (open)." % (len(ports), len(open_ports)),
                                   {"source": src, "target": dst, "ports_probed": len(ports), "ports_open": open_ports[:20],
                                    "sample_ports": sorted(ports)[:15]}, first))
        for port, dsts in by_port.items():
            if len(dsts) >= th.scan_hosts:
                out.append(Finding("HIGH" if len(dsts) >= 100 else "MEDIUM", "host-sweep",
                                   "Host sweep: %s probed port %d on %d hosts" % (src, port, len(dsts)),
                                   "One source tried the same port on many hosts without sending data.",
                                   {"source": src, "port": port, "hosts_probed": len(dsts), "sample_hosts": sorted(dsts)[:10]}, first))
    return out


def syn_flood(a, th):
    per = collections.defaultdict(lambda: [0, set(), 0.0])
    for ts, src, dst, dport in a.syns:
        e = per[(dst, dport)]
        e[0] += 1
        e[1].add(src)
        e[2] = e[2] or ts
    answered = collections.Counter((s, p) for _t, s, _c, p in a.synacks)
    out = []
    for (dst, dport), (n, srcs, first) in per.items():
        if n >= th.synflood_count and answered[(dst, dport)] < n * 0.1:
            out.append(Finding("HIGH", "syn-flood", "Possible SYN flood against %s:%d" % (dst, dport),
                               "%d SYN packets from %d source(s), almost none answered." % (n, len(srcs)),
                               {"target": "%s:%d" % (dst, dport), "syn_count": n, "sources": len(srcs)}, first))
    return out


def beaconing(a, th):
    groups = collections.defaultdict(list)
    for f in a.flow_list:
        if f.proto != "TCP" or 53 in (f.a[1], f.b[1]):
            continue
        if th.beacon_external_only and is_internal(f.b[0]):
            continue
        groups[(f.a[0], f.b[0], f.b[1])].append(f.first_ts)
    out = []
    for (src, dst, dport), times in groups.items():
        if len(times) < th.beacon_min:
            continue
        times.sort()
        gaps = [b - a_ for a_, b in zip(times, times[1:])]
        mean = statistics.mean(gaps)
        if mean < th.beacon_min_interval:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv <= th.beacon_cv:
            out.append(Finding("MEDIUM", "beaconing", "Regular connections from %s to %s:%d (every ~%.0fs)" % (src, dst, dport, mean),
                               "%d connections with very regular spacing (variation %.1f%%), typical of automated check-ins." % (len(times), cv * 100),
                               {"source": src, "destination": "%s:%d" % (dst, dport), "connections": len(times),
                                "mean_interval_s": round(mean, 2), "variation": round(cv, 3)}, times[0]))
    return out


def dns_findings(a, th):
    queries = collections.defaultdict(lambda: {"names": set(), "types": collections.Counter(), "ts": None})
    nx = collections.defaultdict(lambda: {"names": set(), "ts": None})
    for ts, src, dst, msg in a.dns:
        if not msg["qr"]:
            for name, qtype in msg["questions"]:
                reg, sub = registered_domain(name)
                e = queries[(src, reg)]
                if sub:
                    e["names"].add(".".join(sub))
                e["types"][qtype] += 1
                e["ts"] = e["ts"] or ts
        elif msg["rcode"] == "NXDOMAIN":
            e = nx[dst]
            e["ts"] = e["ts"] or ts
            e["names"].update(n for n, _ in msg["questions"])
    out = []
    for (client, reg), e in queries.items():
        subs = e["names"]
        if len(subs) < th.dns_min_unique:
            continue
        avg_len = statistics.mean(len(s.replace(".", "")) for s in subs)
        avg_ent = statistics.mean(entropy(s.split(".")[0]) for s in subs)
        if avg_len >= th.dns_avglen or avg_ent >= th.dns_entropy:
            odd = sum(e["types"][t] for t in ("TXT", "NULL", "10", "16")) / max(1, sum(e["types"].values()))
            out.append(Finding("HIGH" if len(subs) >= 200 else "MEDIUM", "dns-tunneling",
                               "Possible DNS tunneling: %s queried %d unique subdomains of %s" % (client, len(subs), reg),
                               "Long, high-entropy subdomains (avg %.0f chars, entropy %.1f) are typical of data smuggled through DNS." % (avg_len, avg_ent),
                               {"client": client, "domain": reg, "unique_subdomains": len(subs), "avg_label_length": round(avg_len, 1),
                                "avg_entropy": round(avg_ent, 2), "txt_or_null_share": round(odd, 2), "example": sorted(subs)[0]}, e["ts"]))
    for client, e in nx.items():
        if len(e["names"]) >= th.nx_min:
            out.append(Finding("LOW", "nxdomain-storm", "%s received %d NXDOMAIN answers for different names" % (client, len(e["names"])),
                               "Many failed lookups can indicate malware generating random domains (DGA) or a misconfiguration.",
                               {"client": client, "distinct_names": len(e["names"]), "example": sorted(e["names"])[0]}, e["ts"]))
    return out


def arp_spoof(a, th):
    bindings = collections.defaultdict(dict)
    for ts, arp in a.arp:
        for ip, m in ((arp["sender_ip"], arp["sender_mac"]),):
            if m not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff") and ip != "0.0.0.0":
                bindings[ip].setdefault(m, ts)
    return [Finding("HIGH", "arp-spoofing", "Possible ARP spoofing: %s claimed by %d different MAC addresses" % (ip, len(macs)),
                    "The same IP address was announced from several hardware addresses, which is how man-in-the-middle attacks on a LAN work.",
                    {"ip": ip, "macs": sorted(macs)}, min(macs.values()))
            for ip, macs in bindings.items() if len(macs) >= 2]


def icmp_tunnel(a, th):
    per = collections.defaultdict(list)
    for ts, src, dst, typ, _code, plen in a.icmp:
        if typ in (8, 128):
            per[(src, dst)].append((ts, plen))
    out = []
    for (src, dst), items in per.items():
        avg = statistics.mean(p for _, p in items)
        if len(items) >= th.icmp_count and avg >= th.icmp_payload:
            out.append(Finding("MEDIUM", "icmp-tunnel", "Large ICMP echo payloads from %s to %s" % (src, dst),
                               "%d echo requests averaging %.0f payload bytes; ordinary pings carry 32-64 bytes." % (len(items), avg),
                               {"source": src, "destination": dst, "requests": len(items), "avg_payload": round(avg)}, items[0][0]))
    return out


def exfiltration(a, th):
    totals = collections.defaultdict(lambda: [0, 0, None])
    for f in a.flow_list:
        for local, remote, out_b, in_b in ((f.a, f.b, f.a2b_bytes, f.b2a_bytes), (f.b, f.a, f.b2a_bytes, f.a2b_bytes)):
            if is_internal(local[0]) and not is_internal(remote[0]):
                t = totals[(local[0], remote[0])]
                t[0] += out_b
                t[1] += in_b
                t[2] = f.first_ts if t[2] is None else min(t[2], f.first_ts)
                break
    return [Finding("MEDIUM", "large-upload", "%s sent %s to %s" % (src, human(out_b), dst),
                    "Outbound volume is %.0fx the inbound volume, which can indicate data exfiltration." % (out_b / max(in_b, 1)),
                    {"source": src, "destination": dst, "bytes_out": out_b, "bytes_in": in_b}, ts)
            for (src, dst), (out_b, in_b, ts) in totals.items() if out_b >= th.exfil_bytes and out_b >= th.exfil_ratio * max(in_b, 1)]


def human(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


# ---- application-level (reassembled streams) ----------------------------------------

def http_requests(flow):
    data, _ = flow.stream(0)
    return http.parse_messages(data, False) if http.looks_like_http(data, False) else []


def credentials(a, th):
    out = []

    def add(flow, proto, user, detail, ts=None):
        out.append(Finding("HIGH", "cleartext-credentials", "Cleartext %s credentials sent to %s:%d" % (proto, flow.b[0], flow.b[1]),
                           detail, {"protocol": proto, "client": flow.a[0], "server": "%s:%d" % flow.b, "username": user,
                                    "password": "***"}, ts or flow.first_ts))

    for f in a.flow_list:
        if f.proto != "TCP" or not f.segs[0]:
            continue
        for msg in http_requests(f):
            host = msg["headers"].get("host", f.b[0])
            auth = msg["headers"].get("authorization", "")
            if auth.lower().startswith("basic "):
                try:
                    user = base64.b64decode(auth[6:].strip(), validate=True).decode("utf-8", "replace").split(":", 1)[0]
                except (binascii.Error, ValueError):
                    user = "?"
                add(f, "HTTP Basic", user, "Authorization header over unencrypted HTTP to %s%s." % (host, msg["target"][:60]))
            pairs = {}
            if msg["method"] == "POST" and "x-www-form-urlencoded" in msg["headers"].get("content-type", ""):
                pairs = dict(urllib.parse.parse_qsl(msg["body"].decode("latin-1"), keep_blank_values=True))
            elif "?" in msg["target"]:
                pairs = dict(urllib.parse.parse_qsl(msg["target"].split("?", 1)[1], keep_blank_values=True))
            lowered = {k.lower(): v for k, v in pairs.items()}
            if any(k in lowered and lowered[k] for k in PASS_KEYS):
                user = next((lowered[k] for k in USER_KEYS if k in lowered), "?")
                add(f, "HTTP form", user, "A password field was submitted in clear text to %s%s." % (host, msg["target"].split("?")[0][:60]))
        data, _ = f.stream(0)
        text = data[:4096].decode("latin-1")
        if f.b[1] in (21, 110):
            m_user = re.search(r"^USER ([^\r\n]+)", text, re.M)
            if m_user and re.search(r"^PASS [^\r\n]+", text, re.M):
                add(f, "FTP" if f.b[1] == 21 else "POP3", m_user.group(1).strip(), "USER/PASS commands sent without TLS.")
        elif f.b[1] == 143:
            m = re.search(r"^\S+ LOGIN (\S+) \S+", text, re.M | re.I)
            if m:
                add(f, "IMAP", m.group(1).strip('"'), "IMAP LOGIN command sent without TLS.")
        elif f.b[1] in (25, 587):
            m = re.search(r"^AUTH PLAIN (\S+)", text, re.M | re.I)
            if m:
                try:
                    parts = base64.b64decode(m.group(1), validate=True).split(b"\x00")
                    add(f, "SMTP", parts[1].decode("utf-8", "replace") if len(parts) > 1 else "?", "SMTP AUTH PLAIN sent without TLS.")
                except (binascii.Error, ValueError):
                    pass
    return out


def web_findings(a, th):
    out, seen = [], set()
    for f in a.flow_list:
        if f.proto != "TCP":
            continue
        for msg in http_requests(f):
            ua = msg["headers"].get("user-agent", "").lower()
            tool = next((s for s in SCANNER_UAS if s in ua), None)
            if tool and (f.a[0], f.b[0], tool) not in seen:
                seen.add((f.a[0], f.b[0], tool))
                out.append(Finding("MEDIUM", "scanner-user-agent", "Known scanner tool %r used from %s against %s" % (tool, f.a[0], f.b[0]),
                                   "The User-Agent identifies a security scanner.", {"client": f.a[0], "server": f.b[0], "tool": tool}, f.first_ts))
            haystack = urllib.parse.unquote(msg["target"]) + " " + msg["body"][:2000].decode("latin-1")
            for label, rx in ATTACK_PATTERNS:
                if rx.search(haystack) and (f.a[0], f.b[0], label) not in seen:
                    seen.add((f.a[0], f.b[0], label))
                    out.append(Finding("MEDIUM", "web-attack-pattern", "Possible %s attempt from %s against %s" % (label, f.a[0], f.b[0]),
                                       "Request %s %s matches a %s signature." % (msg["method"], msg["target"][:80], label),
                                       {"client": f.a[0], "server": "%s:%d" % f.b, "method": msg["method"], "target": msg["target"][:120],
                                        "kind": label}, f.first_ts))
        data, _ = f.stream(1)
        if http.looks_like_http(data, True):
            for msg in http.parse_messages(data, True):
                body, _ok = http.decompress(msg["body"][:1_000_000], msg["headers"].get("content-encoding"))
                kind = "Windows executable (MZ)" if body[:2] == b"MZ" else "Linux executable (ELF)" if body[:4] == b"\x7fELF" else None
                if kind and (f.b[0], f.a[0], kind) not in seen:
                    seen.add((f.b[0], f.a[0], kind))
                    out.append(Finding("MEDIUM", "executable-download", "%s downloaded over unencrypted HTTP from %s" % (kind, f.b[0]),
                                       "A program file was transferred in clear text and could have been tampered with in transit.",
                                       {"client": f.a[0], "server": "%s:%d" % f.b, "type": kind, "size": len(msg["body"])}, f.first_ts))
    return out


DETECTORS = [port_scan, syn_flood, beaconing, dns_findings, arp_spoof, icmp_tunnel, exfiltration, credentials, web_findings]


def detect_all(analysis, thresholds=None):
    th = thresholds or Thresholds()
    findings = []
    for fn in DETECTORS:
        findings.extend(fn(analysis, th))
    return sorted(findings, key=lambda f: (SEV_ORDER[f.severity], f.ts or 0, f.rule))
