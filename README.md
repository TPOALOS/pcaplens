# pcaplens

Analyse packet captures **without Wireshark, tshark or scapy**. pcaplens is a pure-Python
(standard library only) toolkit that reads `.pcap` / `.pcapng` files, reassembles TCP streams,
and runs a set of detectors for scans, beaconing, DNS tunneling, cleartext credentials, ARP
spoofing and more. It also has the commands you reach for in CTF network forensics: follow a
stream, search payloads for flags, and carve files out of HTTP traffic.

It is an **analysis** tool for blue teams, incident responders and CTF players. It only reads
capture files, sends nothing on the network, and contains no attack code.

## Try it in 30 seconds

No capture handy? pcaplens can generate a synthetic one (every address, name and credential in it is made up):

```bash
python3 -m pcaplens sample demo.pcap
python3 -m pcaplens detect demo.pcap
```

```
Packets  : 549 (331.8 KB) in 116 flows, 607.7 s
Protocols: TCP 421, UDP 111, ICMP 15, ARP 2
TLS server names: secure.example
HTTP hosts      : www.example, ctf.example, shop.example, intranet.example, ...

Findings (14):
  [HIGH  ] cleartext-credentials  Cleartext HTTP Basic credentials sent to 203.0.113.10:80
           Authorization header over unencrypted HTTP to intranet.example/admin.
  [HIGH  ] arp-spoofing           Possible ARP spoofing: 192.168.1.1 claimed by 2 different MAC addresses
  [MEDIUM] port-scan              Port scan: 198.51.100.99 probed 39 ports on 192.168.1.20
  [MEDIUM] dns-tunneling          Possible DNS tunneling: 192.168.1.10 queried 30 unique subdomains of tunnel.example
  [MEDIUM] beaconing              Regular connections from 192.168.1.10 to 198.51.100.66:8443 (every ~60s)
  ...
```

Run it from the repository root (`python3 -m pcaplens ...`). Requires Python 3.8+ (tested on 3.14).

## Commands

| Command | What it does |
|---------|--------------|
| `summary FILE [--json]` | protocols, top talkers, TLS server names (SNI), HTTP hosts |
| `flows FILE [--proto tcp\|udp] [--top N]` | conversations with byte counts and TCP state |
| `detect FILE [--format json] [--min-severity MEDIUM] [--threshold NAME=VALUE]` | run all detectors; exit code `1` when HIGH/MEDIUM findings exist |
| `dns FILE` | queried names with counts, response codes and answers |
| `http FILE` | HTTP request log (time, client, method, host, path) |
| `creds FILE` | cleartext credentials found; **passwords are always masked** |
| `streams FILE` | list reassembled TCP streams with sizes and gaps |
| `stream FILE ID [--direction c2s\|s2c\|both] [--hex]` | print one stream ("Follow TCP stream") |
| `grep FILE PATTERN [-i] [-E] [--base64]` | search stream payloads, UDP payloads and DNS names |
| `grep FILE --flags [--base64]` | find CTF-style `name{...}` flags, also inside base64 chunks |
| `extract FILE --out DIR` | save HTTP response bodies (gzip/deflate/chunked decoded) with a `manifest.json` |
| `report FILE --html out.html [--json out.json]` | self-contained report: findings, flows, DNS, HTTP, SNI |
| `sample OUT [--format pcap\|pcapng]` | write a synthetic demo capture |

## Detectors

| Rule | Severity | Looks for |
|------|----------|-----------|
| `port-scan`, `host-sweep` | MEDIUM / HIGH (100+) | one source making data-less connection attempts to many ports or hosts (SYN, connect() and sweep patterns) |
| `syn-flood` | HIGH | hundreds of unanswered SYNs against one service |
| `beaconing` | MEDIUM | many connections to the same external `ip:port` at very regular intervals (low coefficient of variation) |
| `dns-tunneling` | MEDIUM / HIGH | many unique, long, high-entropy subdomains under one domain |
| `nxdomain-storm` | LOW | many failed lookups for different names (DGA-like or misconfiguration) |
| `arp-spoofing` | HIGH | one IP announced from several MAC addresses |
| `icmp-tunnel` | MEDIUM | many ICMP echo requests with large payloads |
| `large-upload` | MEDIUM | internal host sending far more data to an external host than it receives |
| `cleartext-credentials` | HIGH | HTTP Basic, HTTP form/query passwords, FTP, POP3, IMAP, SMTP AUTH PLAIN over unencrypted connections |
| `web-attack-pattern`, `scanner-user-agent` | MEDIUM | SQLi / traversal / XSS / command-injection / log4shell signatures in requests, known scanner User-Agents |
| `executable-download` | MEDIUM | Windows (MZ) or Linux (ELF) programs downloaded over plain HTTP |

Tune any threshold with `--threshold NAME=VALUE` (for example `--threshold scan_ports=30 --threshold exfil_bytes=1000000`).
Names: `scan_ports`, `scan_hosts`, `synflood_count`, `beacon_min`, `beacon_min_interval`, `beacon_cv`,
`beacon_external_only`, `dns_min_unique`, `dns_avglen`, `dns_entropy`, `nx_min`, `icmp_count`,
`icmp_payload`, `exfil_bytes`, `exfil_ratio`. "Internal" means RFC 1918, loopback, link-local and ULA addresses.

## CTF forensics workflow

```bash
python3 -m pcaplens summary challenge.pcap          # what is in here?
python3 -m pcaplens streams challenge.pcap          # list TCP streams
python3 -m pcaplens stream challenge.pcap 4         # follow stream 4
python3 -m pcaplens grep challenge.pcap --flags --base64
python3 -m pcaplens extract challenge.pcap --out extracted/   # then inspect files with `file` / `strings`
```

`extract` names files by content hash and content type (never by anything the server sent, so no path
traversal), maps executables to `.bin`, caps decompression (zip-bomb safe) and total size. **Never open or run
extracted files.**

## Safety and privacy

- Read-only: it only reads capture files and never touches the network.
- Credentials are masked everywhere (text, JSON, HTML, CLI). Usernames are shown, passwords never.
- The HTML report escapes all captured text (hostnames, URLs, DNS names, User-Agents), has no JavaScript and a restrictive CSP.
- All parsers are bounds-checked and fuzz-tested: malformed or truncated packets are counted, not fatal.
- Only analyse captures you are authorised to have. Packet captures often contain personal data and credentials.

## How it works

```
pcaplens/pcap.py      pcap (LE/BE, micro/nanosecond) and pcapng readers, streaming
pcaplens/decode.py    Ethernet/VLAN/Linux-cooked/loopback/raw, IPv4/IPv6, TCP/UDP/ICMP/ARP, DNS (compression-safe), TLS SNI
pcaplens/analyze.py   one pass: flows, TCP reassembly (reordering, duplicates, wraparound, gaps), event lists
pcaplens/http.py      HTTP/1.x parsing: Content-Length, chunked, gzip/deflate with size caps
pcaplens/detect.py    the detectors and their thresholds
pcaplens/report.py    text, JSON and HTML reports
pcaplens/synth.py     synthetic capture builder used by `sample` and the tests
pcaplens/cli.py       command line
```

On synthetic TCP traffic it processed about 200,000 packets per second on a laptop (60,000 packets in 0.3 s); real
captures with larger payloads and many flows will be slower. Streams are capped at 8 MB per direction.

## Limitations

- Heuristics, not verdicts: detectors can produce false positives (monitoring systems look like beacons, backup jobs look like uploads) and miss slow or well-disguised activity. Tune thresholds for your network.
- No TLS decryption: encrypted traffic is seen as flows, SNI and sizes only. No HTTP/2, QUIC or WebSocket parsing; HTTP/1.x only.
- No IP fragment reassembly (later fragments are skipped), no tunnel decapsulation (GRE, VXLAN, IPsec), no `.gz`-compressed captures.
- Streams are keyed by 5-tuple: if a client reuses a source port later, those connections share one stream.
- pcapng: section header, interface description, enhanced and simple packet blocks (other block types are skipped).
- Timestamps are shown in UTC.

## Tests

```bash
python3 -m unittest -v
```

107 tests: file formats, truncated and corrupted files, fuzzed decoding, DNS compression loops, stream
reassembly edge cases, each detector with positive and negative cases, report escaping, and every CLI command.
Test captures are generated in memory from `synth.py`; the repository contains no real traffic.

## License

MIT (c) TPOALOS
