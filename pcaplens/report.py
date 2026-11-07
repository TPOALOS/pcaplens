"""Summaries and reports: text, JSON and a self-contained HTML page (no JavaScript)."""
import collections
import html
import json
import time

from . import __version__
from .detect import http_requests

SEV_CLASS = {"HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}


def iso(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime(ts)) if ts else "-"


def human(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return "%d B" % n if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024.0


def http_log(analysis, limit=None):
    rows = []
    for f in analysis.flow_list:
        if f.proto != "TCP" or not f.segs[0]:
            continue
        for msg in http_requests(f):
            rows.append({"time": f.first_ts, "client": f.a[0], "server": "%s:%d" % f.b, "method": msg["method"],
                         "host": msg["headers"].get("host", ""), "target": msg["target"],
                         "user_agent": msg["headers"].get("user-agent", "")})
    rows.sort(key=lambda r: r["time"])
    return rows[:limit] if limit else rows


def dns_log(analysis):
    """Unique queried names with counts, types and the most recent response code/answers."""
    stats = collections.OrderedDict()
    for ts, src, dst, msg in analysis.dns:
        for name, qtype in msg["questions"]:
            e = stats.setdefault((name, qtype), {"name": name, "type": qtype, "count": 0, "rcode": None, "answers": []})
            if not msg["qr"]:
                e["count"] += 1
            else:
                e["rcode"] = msg["rcode"]
                e["answers"] = [a["data"] for a in msg["answers"]][:5]
    return sorted(stats.values(), key=lambda e: (-e["count"], e["name"]))


def summary(analysis):
    a = analysis
    sni = collections.Counter(f.sni for f in a.flow_list if f.sni)
    http_hosts = collections.Counter(r["host"] or r["server"] for r in http_log(a))
    top_flows = sorted(a.flow_list, key=lambda f: -f.bytes)[:10]
    return {
        "file": a.path, "format": a.info.get("format"), "packets": a.packets, "bytes": a.bytes,
        "start": a.first_ts, "end": a.last_ts, "duration_s": round(a.duration(), 3), "malformed_packets": a.malformed,
        "warnings": a.info.get("warnings", []), "flows": len(a.flow_list),
        "protocols": dict(a.protocols.most_common()),
        "top_talkers": [{"ip": ip, "bytes": n} for ip, n in a.talkers.most_common(10)],
        "top_flows": [f.to_dict() for f in top_flows],
        "tls_server_names": dict(sni.most_common(20)),
        "http_hosts": dict(http_hosts.most_common(20)),
        "dns_names": len({q[0] for _t, _s, _d, m in a.dns if not m["qr"] for q in m["questions"]}),
    }


def render_text(analysis, findings):
    s = summary(analysis)
    out = ["pcaplens %s" % __version__, "File     : %s (%s)" % (s["file"], s["format"]),
           "Packets  : %d (%s) in %d flows, %.1f s" % (s["packets"], human(s["bytes"]), s["flows"], s["duration_s"]),
           "Time     : %s -> %s" % (iso(s["start"]), iso(s["end"]))]
    if s["malformed_packets"]:
        out.append("Malformed: %d packet(s) could not be fully decoded" % s["malformed_packets"])
    for w in s["warnings"]:
        out.append("Warning  : " + w)
    out.append("Protocols: " + ", ".join("%s %d" % kv for kv in s["protocols"].items()))
    out.append("\nTop talkers:")
    out += ["  %-40s %s" % (t["ip"], human(t["bytes"])) for t in s["top_talkers"][:5]]
    if s["tls_server_names"]:
        out.append("\nTLS server names: " + ", ".join(s["tls_server_names"]))
    if s["http_hosts"]:
        out.append("HTTP hosts      : " + ", ".join(s["http_hosts"]))
    out.append("\nFindings (%d):" % len(findings))
    if not findings:
        out.append("  none")
    for f in findings:
        out.append("  [%-6s] %-22s %s" % (f.severity, f.rule, f.title))
        out.append("           %s" % f.detail)
    return "\n".join(out)


def render_json(analysis, findings):
    return json.dumps({"tool": "pcaplens " + __version__, "summary": summary(analysis),
                       "findings": [f.to_dict() for f in findings]}, indent=2, default=str)


CSS = """body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#0f1318;color:#e6e9ee}main{max-width:1000px;margin:0 auto;padding:20px 16px}
h1,h2{line-height:1.2}h2{margin-top:28px;border-bottom:1px solid #2a313c;padding-bottom:4px}table{width:100%;border-collapse:collapse;font-size:14px}
th,td{padding:6px 8px;border-bottom:1px solid #2a313c;text-align:left;vertical-align:top;word-break:break-word}.muted{color:#8b95a3}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-weight:600;font-size:12px;color:#111}.high{background:#e5696a}.med{background:#e8b04a}
.low{background:#6fb3e0}.info{background:#9aa5b1}.card{background:#171c24;border:1px solid #2a313c;border-radius:8px;padding:12px;margin:10px 0}code{font-family:ui-monospace,monospace}"""


def render_html(analysis, findings):
    e = lambda v: html.escape(str(v), quote=True)
    s = summary(analysis)
    out = ['<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
           '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">'
           "<title>pcaplens report</title><style>%s</style></head><body><main>" % CSS,
           "<h1>pcaplens report</h1><p class=\"muted\">%s &middot; %s &middot; generated by pcaplens %s</p>" % (e(s["file"]), e(s["format"]), e(__version__)),
           "<div class=\"card\"><b>%d</b> packets (%s) in <b>%d</b> flows over %.1f s<br>%s &rarr; %s</div>" % (
               s["packets"], e(human(s["bytes"])), s["flows"], s["duration_s"], e(iso(s["start"])), e(iso(s["end"])))]
    out.append("<h2>Findings (%d)</h2>" % len(findings))
    if not findings:
        out.append("<p class=\"muted\">No findings.</p>")
    for f in findings:
        out.append('<div class="card"><span class="badge %s">%s</span> <b>%s</b> <code>%s</code><br>%s<br><span class="muted">%s</span></div>' % (
            SEV_CLASS[f.severity], e(f.severity), e(f.title), e(f.rule), e(f.detail), e(json.dumps(f.evidence, default=str))))

    def table(title, head, rows):
        out.append("<h2>%s</h2><table><tr>%s</tr>" % (e(title), "".join("<th>%s</th>" % e(h) for h in head)))
        out.extend("<tr>%s</tr>" % "".join("<td>%s</td>" % e(c) for c in r) for r in rows)
        out.append("</table>")

    table("Protocols", ["Protocol", "Packets"], s["protocols"].items())
    table("Top talkers", ["Address", "Bytes"], [(t["ip"], human(t["bytes"])) for t in s["top_talkers"]])
    table("Largest flows", ["Proto", "Source", "Destination", "Bytes", "State"],
          [(f["proto"], f["src"], f["dst"], human(f["bytes"]), f["state"]) for f in s["top_flows"]])
    if s["tls_server_names"]:
        table("TLS server names (SNI)", ["Name", "Connections"], s["tls_server_names"].items())
    rows = http_log(analysis, 100)
    if rows:
        table("HTTP requests (first 100)", ["Time", "Client", "Method", "Host", "Path", "User-Agent"],
              [(iso(r["time"]), r["client"], r["method"], r["host"], r["target"][:120], r["user_agent"][:80]) for r in rows])
    names = dns_log(analysis)[:50]
    if names:
        table("DNS names (top 50)", ["Name", "Type", "Queries", "Result", "Answers"],
              [(n["name"], n["type"], n["count"], n["rcode"] or "-", ", ".join(n["answers"])) for n in names])
    out.append("</main></body></html>")
    return "".join(out)
