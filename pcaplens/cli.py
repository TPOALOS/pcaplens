"""Command line interface."""
import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import sys

from . import __version__, detect, http, pcap, report, synth
from .analyze import analyze_file

EXT = {"text/html": ".html", "text/plain": ".txt", "text/css": ".css", "application/json": ".json", "image/png": ".png",
       "image/jpeg": ".jpg", "image/gif": ".gif", "application/pdf": ".pdf", "text/javascript": ".txt",
       "application/javascript": ".txt", "application/xml": ".xml", "text/xml": ".xml"}
FLAG_RE = r"(?i)[a-z0-9_]{2,12}\{[^}\r\n]{3,100}\}"
B64_RE = re.compile(rb"[A-Za-z0-9+/]{16,}={0,2}")
MAX_EXTRACT_TOTAL = 512 * 1024 * 1024


def printable(data, limit=None):
    data = data[:limit] if limit else data
    return "".join(chr(b) if 32 <= b < 127 or b in (9, 10, 13) else "." for b in data)


def hexdump(data, limit=4096):
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        lines.append("%08x  %-47s  %s" % (off, " ".join("%02x" % b for b in chunk), printable(chunk).replace("\n", ".").replace("\r", ".").replace("\t", ".")))
    return "\n".join(lines)


def parse_thresholds(items):
    overrides = {}
    for item in items or []:
        k, _, v = item.partition("=")
        if not v:
            raise ValueError("threshold must look like name=value, got %r" % item)
        default = getattr(detect.Thresholds, k, None)
        if default is None:
            raise ValueError("unknown threshold %r (see README)" % k)
        overrides[k] = (v.lower() in ("1", "true", "yes")) if isinstance(default, bool) else type(default)(v)
    return detect.Thresholds(**overrides)


def build_parser():
    ap = argparse.ArgumentParser(prog="pcaplens", description="Analyse packet captures (pcap/pcapng) without Wireshark or scapy.")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def cmd(name, helptext, file=True):
        p = sub.add_parser(name, help=helptext)
        if file:
            p.add_argument("file", help="capture file (.pcap or .pcapng)")
        return p

    p = cmd("summary", "overview: protocols, talkers, names")
    p.add_argument("--json", action="store_true")
    p = cmd("flows", "list conversations")
    p.add_argument("--top", type=int, default=25)
    p.add_argument("--proto", choices=("tcp", "udp"))
    p = cmd("detect", "run the detectors")
    p.add_argument("--format", choices=("text", "json"), default="text")
    p.add_argument("--min-severity", choices=("LOW", "MEDIUM", "HIGH"), default="LOW")
    p.add_argument("--threshold", action="append", metavar="NAME=VALUE", help="tune a detector threshold (repeatable)")
    p = cmd("dns", "list DNS names")
    p.add_argument("--top", type=int, default=50)
    cmd("http", "list HTTP requests")
    cmd("creds", "show cleartext credentials found (passwords are masked)")
    cmd("streams", "list TCP streams")
    p = cmd("stream", "print one reassembled TCP stream")
    p.add_argument("id", type=int)
    p.add_argument("--direction", choices=("c2s", "s2c", "both"), default="both")
    p.add_argument("--hex", action="store_true")
    p = cmd("extract", "save HTTP response bodies to a directory (never open or run them)")
    p.add_argument("--out", required=True)
    p = cmd("grep", "search stream payloads and DNS names")
    p.add_argument("pattern", nargs="?")
    p.add_argument("-i", "--ignore-case", action="store_true")
    p.add_argument("-E", "--regex", action="store_true", help="treat the pattern as a regular expression")
    p.add_argument("--flags", action="store_true", help="look for CTF-style flags like name{...}")
    p.add_argument("--base64", action="store_true", help="also search inside base64-looking chunks")
    p = cmd("report", "write an HTML (and optional JSON) report")
    p.add_argument("--html", required=True)
    p.add_argument("--json", dest="json_out")
    p = cmd("sample", "write a synthetic demo capture", file=False)
    p.add_argument("out")
    p.add_argument("--format", choices=("pcap", "pcapng"), default="pcap")
    return ap


def out_line(out, text=""):
    out.write(text + "\n")


def cmd_flows(a, args, out):
    rows = [f for f in a.flow_list if not args.proto or f.proto.lower() == args.proto]
    rows.sort(key=lambda f: -f.bytes)
    out_line(out, "%-4s %-5s %-24s %-24s %9s %10s %-11s" % ("id", "proto", "initiator", "responder", "packets", "bytes", "state"))
    for f in rows[:args.top]:
        out_line(out, "%-4d %-5s %-24s %-24s %9d %10s %-11s" % (f.id, f.proto, "%s:%s" % f.a, "%s:%s" % f.b, f.packets, report.human(f.bytes), f.state))
    out_line(out, "\n%d flow(s) total" % len(rows))


def cmd_streams(a, args, out):
    out_line(out, "%-4s %-24s %-24s %9s %9s %-11s %s" % ("id", "client", "server", "c2s", "s2c", "state", "gaps"))
    for f in a.flow_list:
        if f.proto == "TCP" and (f.segs[0] or f.segs[1]):
            out_line(out, "%-4d %-24s %-24s %9s %9s %-11s %d" % (f.id, "%s:%s" % f.a, "%s:%s" % f.b, report.human(len(f.stream(0)[0])),
                                                                  report.human(len(f.stream(1)[0])), f.state, f.stream(0)[1] + f.stream(1)[1]))


def cmd_stream(a, args, out):
    flow = a.flow_list[args.id] if 0 <= args.id < len(a.flow_list) else None
    if flow is None or flow.proto != "TCP":
        raise ValueError("no TCP stream with id %d (see `pcaplens streams`)" % args.id)
    for direction, label in ((0, "c2s"), (1, "s2c")):
        if args.direction not in ("both", label):
            continue
        data, gaps = flow.stream(direction)
        out_line(out, "=== %s  %s:%s -> %s:%s  (%d bytes%s) ===" % (label, *(flow.a if direction == 0 else flow.b), *(flow.b if direction == 0 else flow.a),
                                                                      len(data), ", %d gap(s)" % gaps if gaps else ""))
        out_line(out, hexdump(data) if args.hex else printable(data, 200000))


def cmd_extract(a, args, out):
    os.makedirs(args.out, exist_ok=True)
    manifest, total = [], 0
    for f in a.flow_list:
        if f.proto != "TCP":
            continue
        reqs = http_requests_for(f)
        data, _ = f.stream(1)
        if not http.looks_like_http(data, True):
            continue
        for i, msg in enumerate(http.parse_messages(data, True)):
            body, ok = http.decompress(msg["body"], msg["headers"].get("content-encoding"))
            if not body:
                continue
            total += len(body)
            if total > MAX_EXTRACT_TOTAL:
                raise ValueError("extraction limit of %s reached" % report.human(MAX_EXTRACT_TOTAL))
            sha = hashlib.sha256(body).hexdigest()
            ctype = msg["headers"].get("content-type", "").split(";")[0].strip().lower()
            name = "%03d_%02d_%s%s" % (f.id, i, sha[:12], EXT.get(ctype, ".bin"))   # never use server-supplied names
            try:
                with open(os.path.join(args.out, name), "xb") as fh:
                    fh.write(body)
            except FileExistsError:
                pass
            req = reqs[i] if i < len(reqs) else None
            manifest.append({"file": name, "flow": f.id, "client": f.a[0], "server": "%s:%d" % f.b, "status": msg["status"],
                             "content_type": ctype, "size": len(body), "sha256": sha, "complete": ok and not msg["truncated"],
                             "url": ("http://%s%s" % (req["headers"].get("host", f.b[0]), req["target"])) if req else None,
                             "looks_executable": body[:2] == b"MZ" or body[:4] == b"\x7fELF"})
    with open(os.path.join(args.out, "manifest.json"), "w") as fh:
        json.dump(manifest, fh, indent=2)
    out_line(out, "pcaplens: extracted %d object(s) to %s (do not open or run them; see manifest.json)" % (len(manifest), args.out))


def http_requests_for(flow):
    return detect.http_requests(flow) if flow.segs[0] else []


def cmd_grep(a, args, out):
    if args.flags:
        pat, flags = FLAG_RE, 0
        rx = re.compile(pat.encode(), re.I)
    else:
        if not args.pattern:
            raise ValueError("give a pattern or use --flags")
        pat = args.pattern if args.regex else re.escape(args.pattern)
        rx = re.compile(pat.encode(), re.I if args.ignore_case else 0)
    hits = 0

    def search(label, data):
        nonlocal hits
        sources = [("", data)]
        if args.base64:
            for m in B64_RE.finditer(data):
                try:
                    sources.append((" (base64 @%d)" % m.start(), base64.b64decode(m.group(0) + b"=" * (-len(m.group(0)) % 4))))
                except (binascii.Error, ValueError):
                    continue
        for note, blob in sources:
            for m in rx.finditer(blob):
                hits += 1
                if hits <= 200:
                    ctx = blob[max(0, m.start() - 20):m.end() + 20]
                    out_line(out, "%s%s @%d: %s" % (label, note, m.start(), printable(ctx).replace("\n", " ")))

    for f in a.flow_list:
        if f.proto == "TCP":
            for d, name in ((0, "c2s"), (1, "s2c")):
                search("stream#%d %s" % (f.id, name), f.stream(d)[0])
        elif f.udp:
            search("udp#%d" % f.id, bytes(f.udp))
    for _ts, _s, _d, msg in a.dns:
        for name, _t in msg["questions"]:
            search("dns-name", name.encode())
    out_line(out, "pcaplens: %d match(es)%s" % (hits, " (first 200 shown)" if hits > 200 else ""))
    return 0 if hits else 1


def run(argv=None, out=None):
    out = out or sys.stdout
    args = build_parser().parse_args(argv)
    if args.cmd == "sample":
        b = synth.demo_capture()
        (b.write_pcapng if args.format == "pcapng" else b.write_pcap)(args.out)
        out_line(out, "pcaplens: wrote synthetic demo capture to %s (all addresses and credentials are made up)" % args.out)
        return 0
    a = analyze_file(args.file)
    if args.cmd == "summary":
        out_line(out, json.dumps(report.summary(a), indent=2, default=str) if args.json else report.render_text(a, []).split("\nFindings")[0])
    elif args.cmd == "flows":
        cmd_flows(a, args, out)
    elif args.cmd == "detect":
        th = parse_thresholds(args.threshold)
        limit = detect.SEV_ORDER[args.min_severity]
        findings = [f for f in detect.detect_all(a, th) if detect.SEV_ORDER[f.severity] <= limit]
        out_line(out, report.render_json(a, findings) if args.format == "json" else report.render_text(a, findings))
        return 1 if any(f.severity in ("HIGH", "MEDIUM") for f in findings) else 0
    elif args.cmd == "dns":
        out_line(out, "%-50s %-6s %7s  %-9s %s" % ("name", "type", "queries", "result", "answers"))
        for n in report.dns_log(a)[:args.top]:
            out_line(out, "%-50s %-6s %7d  %-9s %s" % (n["name"][:50], n["type"], n["count"], n["rcode"] or "-", ", ".join(n["answers"])))
    elif args.cmd == "http":
        for r in report.http_log(a):
            out_line(out, "%s  %-15s -> %-21s %-6s http://%s%s" % (report.iso(r["time"]), r["client"], r["server"], r["method"], r["host"], r["target"][:100]))
    elif args.cmd == "creds":
        found = detect.credentials(a, detect.Thresholds())
        for f in found:
            ev = f.evidence
            out_line(out, "%-11s %-15s -> %-21s user=%s password=%s" % (ev["protocol"], ev["client"], ev["server"], ev["username"], ev["password"]))
        out_line(out, "pcaplens: %d credential exposure(s); passwords are never printed" % len(found))
        return 1 if found else 0
    elif args.cmd == "streams":
        cmd_streams(a, args, out)
    elif args.cmd == "stream":
        cmd_stream(a, args, out)
    elif args.cmd == "extract":
        cmd_extract(a, args, out)
    elif args.cmd == "grep":
        return cmd_grep(a, args, out)
    elif args.cmd == "report":
        findings = detect.detect_all(a)
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(report.render_html(a, findings))
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8") as fh:
                fh.write(report.render_json(a, findings))
        out_line(out, "pcaplens: report written to %s (%d finding(s))" % (args.html, len(findings)))
    return 0


def main(argv=None, out=None):
    try:
        return run(argv, out)
    except (OSError, ValueError, KeyError, pcap.PcapError) as exc:
        sys.stderr.write("pcaplens: error: %s\n" % exc)
        return 2
