import json
import tempfile
import unittest

from pcaplens import detect, report, synth

from .util import analysis_of

CLIENT = synth.CLIENT


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name

    def run_detect(self, builder, **th):
        self.analysis = analysis_of(builder, self.dir)
        return detect.detect_all(self.analysis, detect.Thresholds(**th))

    def rules(self, builder, **th):
        return {f.rule for f in self.run_detect(builder, **th)}

    def one(self, builder, rule, **th):
        found = [f for f in self.run_detect(builder, **th) if f.rule == rule]
        self.assertEqual(len(found), 1, "%s findings for %s" % (len(found), rule))
        return found[0]


class CleanTrafficTests(Base):
    def test_normal_browsing_has_no_findings(self):
        b = synth.Builder()
        synth.normal_browsing(b)
        synth.tls_visit(b)
        for i in range(5):
            b.dns_query(CLIENT, synth.RESOLVER, "www.example.org", sport=33000 + i, ident=i)
            b.dns_response(CLIENT, synth.RESOLVER, "www.example.org", [(1, bytes([203, 0, 113, 5]))], sport=33000 + i, ident=i)
        self.assertEqual(self.run_detect(b), [])

    def test_empty_capture(self):
        self.assertEqual(self.run_detect(synth.Builder()), [])


class ScanTests(Base):
    def test_vertical_scan(self):
        b = synth.Builder()
        synth.port_scan(b, ports=range(1, 31))
        f = self.one(b, "port-scan")
        self.assertEqual((f.evidence["source"], f.evidence["target"], f.evidence["ports_probed"]), (synth.ATTACKER, synth.SERVER, 30))

    def test_scan_below_threshold_is_ignored(self):
        b = synth.Builder()
        synth.port_scan(b, ports=range(1, 10))
        self.assertNotIn("port-scan", self.rules(b))
        self.assertIn("port-scan", self.rules(b, scan_ports=5))

    def test_open_ports_are_reported(self):
        b = synth.Builder()
        synth.port_scan(b, ports=range(20, 40))
        b.tcp(synth.SERVER, 22, synth.ATTACKER, 41002, synth.SYN | synth.ACK, 1, 2)
        self.assertEqual(self.one(b, "port-scan").evidence["ports_open"], [22])

    def test_normal_connections_to_many_ports_are_not_a_scan(self):
        b = synth.Builder()
        for i, port in enumerate(range(8000, 8030)):
            b.tcp_session(CLIENT, 50000 + i, synth.WEB, port, b"hi", b"ok")
        self.assertNotIn("port-scan", self.rules(b))

    def test_host_sweep(self):
        b = synth.Builder()
        for i in range(1, 25):
            b.syn_only(synth.ATTACKER, 42000 + i, "192.168.1.%d" % (100 + i), 445)
        f = self.one(b, "host-sweep")
        self.assertEqual((f.evidence["port"], f.evidence["hosts_probed"]), (445, 24))

    def test_syn_flood(self):
        b = synth.Builder()
        for i in range(400):
            b.syn_only("198.51.100.%d" % (1 + i % 50), 10000 + i, synth.SERVER, 80)
        f = self.one(b, "syn-flood")
        self.assertEqual(f.evidence["syn_count"], 400)
        self.assertEqual(f.severity, "HIGH")

    def test_busy_server_with_answers_is_not_flood(self):
        b = synth.Builder()
        for i in range(400):
            b.tcp_session("198.51.100.%d" % (1 + i % 50), 10000 + i, synth.SERVER, 80, b"x", b"y")
        self.assertNotIn("syn-flood", self.rules(b))


class BeaconTests(Base):
    def test_regular_beacon(self):
        b = synth.Builder()
        synth.beacon(b, interval=30, count=10, jitter=0.4)
        f = self.one(b, "beaconing")
        self.assertEqual(f.evidence["connections"], 10)
        self.assertAlmostEqual(f.evidence["mean_interval_s"], 30, delta=1)

    def test_irregular_traffic_is_not_a_beacon(self):
        b = synth.Builder()
        for i in range(10):
            b.advance(b.rng.uniform(1, 200))
            b.tcp_session(CLIENT, 52000 + i, synth.C2, 8443, b"x", b"y")
        self.assertNotIn("beaconing", self.rules(b))

    def test_few_connections_not_flagged(self):
        b = synth.Builder()
        synth.beacon(b, interval=30, count=4)
        self.assertNotIn("beaconing", self.rules(b))

    def test_internal_destination_ignored_by_default(self):
        b = synth.Builder()
        synth.beacon(b, interval=30, count=10, c2="192.168.1.50")
        self.assertNotIn("beaconing", self.rules(b))
        self.assertIn("beaconing", self.rules(b, beacon_external_only=False))

    def test_fast_polling_below_min_interval_ignored(self):
        b = synth.Builder()
        synth.beacon(b, interval=0.2, count=10, jitter=0.0)
        self.assertNotIn("beaconing", self.rules(b))


class DnsTests(Base):
    def test_tunnel(self):
        b = synth.Builder()
        synth.dns_tunnel(b, count=30)
        f = self.one(b, "dns-tunneling")
        self.assertEqual((f.evidence["domain"], f.evidence["unique_subdomains"]), ("tunnel.example", 30))
        self.assertGreater(f.evidence["avg_label_length"], 30)

    def test_many_short_normal_names_are_not_a_tunnel(self):
        b = synth.Builder()
        for i in range(40):
            b.dns_query(CLIENT, synth.RESOLVER, "host%d.cdn.example" % i, sport=34000 + i, ident=i)
        self.assertNotIn("dns-tunneling", self.rules(b))

    def test_second_level_suffixes(self):
        self.assertEqual(detect.registered_domain("a.b.example.co.uk"), ("example.co.uk", ["a", "b"]))
        self.assertEqual(detect.registered_domain("a.b.example.org"), ("example.org", ["a", "b"]))
        self.assertEqual(detect.registered_domain("example.org"), ("example.org", []))

    def test_entropy(self):
        self.assertEqual(detect.entropy(""), 0.0)
        self.assertEqual(detect.entropy("aaaa"), 0.0)
        self.assertAlmostEqual(detect.entropy("abcd"), 2.0)

    def test_nxdomain_storm(self):
        b = synth.Builder()
        synth.nxdomain_storm(b, count=25)
        f = self.one(b, "nxdomain-storm")
        self.assertEqual((f.severity, f.evidence["distinct_names"]), ("LOW", 25))
        c = synth.Builder()
        synth.nxdomain_storm(c, count=5)
        self.assertNotIn("nxdomain-storm", self.rules(c))


class LanTests(Base):
    def test_arp_spoof(self):
        b = synth.Builder()
        synth.arp_spoof(b)
        f = self.one(b, "arp-spoofing")
        self.assertEqual(f.evidence["ip"], "192.168.1.1")
        self.assertEqual(len(f.evidence["macs"]), 2)

    def test_consistent_arp_is_fine(self):
        b = synth.Builder()
        mac = synth.ip_mac("192.168.1.1", 5)
        for _ in range(3):
            b.arp(2, mac, "192.168.1.1", synth.ip_mac(CLIENT, 2), CLIENT)
            b.advance(1)
        b.arp(1, b"\x00" * 6, "0.0.0.0", b"\xff" * 6, "192.168.1.1")  # ARP probe: sender 0.0.0.0 is ignored
        self.assertNotIn("arp-spoofing", self.rules(b))

    def test_icmp_tunnel_vs_normal_ping(self):
        b = synth.Builder()
        synth.icmp_tunnel(b, count=15)
        self.assertEqual(self.one(b, "icmp-tunnel").evidence["avg_payload"], 200)
        c = synth.Builder()
        for _ in range(30):
            c.icmp_echo(CLIENT, synth.C2, b"p" * 32)
        self.assertNotIn("icmp-tunnel", self.rules(c))

    def test_large_upload(self):
        b = synth.Builder()
        synth.large_upload(b, size=300_000)
        self.assertNotIn("large-upload", self.rules(b))
        f = self.one(b, "large-upload", exfil_bytes=100_000)
        self.assertEqual((f.evidence["source"], f.evidence["destination"]), (CLIENT, synth.C2))

    def test_big_download_is_not_exfil(self):
        b = synth.Builder()
        b.tcp_session(CLIENT, 50400, synth.C2, 443, b"GET", b"Z" * 300_000, mss=1400)
        self.assertNotIn("large-upload", self.rules(b, exfil_bytes=100_000))


class ApplicationTests(Base):
    def creds(self, builder):
        return [f for f in self.run_detect(builder) if f.rule == "cleartext-credentials"]

    def test_http_form_basic_and_ftp(self):
        b = synth.Builder()
        synth.cleartext_http_login(b)
        synth.http_basic_auth(b)
        synth.ftp_login(b)
        found = {f.evidence["protocol"]: f.evidence["username"] for f in self.creds(b)}
        self.assertEqual(found, {"HTTP form": "alice", "HTTP Basic": "bob", "FTP": "carol"})

    def test_passwords_never_appear_in_any_output(self):
        b = synth.Builder()
        synth.cleartext_http_login(b)
        synth.http_basic_auth(b)
        synth.ftp_login(b)
        findings = self.run_detect(b)
        blob = json.dumps([f.to_dict() for f in findings]) + report.render_text(self.analysis, findings) + report.render_html(self.analysis, findings) \
            + report.render_json(self.analysis, findings)
        for secret in ("fake-demo-pass-1", "fake-basic-pass-2", "fake-ftp-pass-3"):
            self.assertNotIn(secret, blob)

    def test_get_query_with_password_and_imap_pop3_smtp(self):
        import base64
        b = synth.Builder()
        synth.http_get(b, path="/login?user=dave&password=fake-get-pass-4", cport=50700)
        b.tcp_session(CLIENT, 50701, "198.51.100.31", 110, b"USER erin\r\nPASS fake-pop-pass-5\r\n", b"+OK\r\n+OK\r\n")
        b.tcp_session(CLIENT, 50702, "198.51.100.32", 143, b"a1 LOGIN frank fake-imap-pass-6\r\n", b"a1 OK\r\n")
        plain = base64.b64encode(b"\x00grace\x00fake-smtp-pass-7")
        b.tcp_session(CLIENT, 50703, "198.51.100.33", 587, b"AUTH PLAIN " + plain + b"\r\n", b"235 ok\r\n")
        found = {f.evidence["protocol"]: f.evidence["username"] for f in self.creds(b)}
        self.assertEqual(found, {"HTTP form": "dave", "POP3": "erin", "IMAP": "frank", "SMTP": "grace"})

    def test_login_page_without_password_is_not_flagged(self):
        b = synth.Builder()
        synth.http_get(b, path="/login?next=/home")
        self.assertEqual(self.creds(b), [])

    def test_encrypted_traffic_not_flagged(self):
        b = synth.Builder()
        b.tcp_session(CLIENT, 50800, synth.WEB, 443, b"\x17\x03\x03 password=notreallyhttp", b"\x17\x03\x03 ok")
        self.assertEqual(self.creds(b), [])

    def test_web_attacks_and_scanner_ua(self):
        b = synth.Builder()
        synth.scanner_and_attack_requests(b)
        kinds = {f.evidence.get("kind") or f.evidence.get("tool") for f in self.run_detect(b) if f.rule in ("web-attack-pattern", "scanner-user-agent")}
        self.assertEqual(kinds, {"sqlmap", "SQL injection", "path traversal", "sensitive file access"})

    def test_normal_requests_not_flagged(self):
        b = synth.Builder()
        synth.http_get(b, path="/search?q=union+station+hours&page=2")
        self.assertEqual([f for f in self.run_detect(b) if f.rule.startswith("web-")], [])

    def test_executable_download(self):
        b = synth.Builder()
        synth.exe_download(b)
        self.assertIn("Windows executable", self.one(b, "executable-download").title)
        c = synth.Builder()
        synth.http_get(c, path="/elf", body=b"\x7fELF" + b"\x00" * 50)
        self.assertIn("Linux executable", self.one(c, "executable-download").title)
        d = synth.Builder()
        synth.http_get(d, path="/page", body=b"just text")
        self.assertNotIn("executable-download", self.rules(d))

    def test_demo_capture_triggers_every_detector(self):
        rules = self.rules(synth.demo_capture(), exfil_bytes=100_000)
        expected = {"port-scan", "beaconing", "dns-tunneling", "nxdomain-storm", "arp-spoofing", "icmp-tunnel", "large-upload",
                    "cleartext-credentials", "web-attack-pattern", "scanner-user-agent", "executable-download"}
        self.assertTrue(expected <= rules, expected - rules)

    def test_findings_sorted_by_severity(self):
        order = [detect.SEV_ORDER[f.severity] for f in self.run_detect(synth.demo_capture())]
        self.assertEqual(order, sorted(order))


class ThresholdTests(unittest.TestCase):
    def test_overrides_and_unknown(self):
        self.assertEqual(detect.Thresholds(scan_ports=3).scan_ports, 3)
        self.assertEqual(detect.Thresholds().scan_ports, 15)
        with self.assertRaises(KeyError):
            detect.Thresholds(nonsense=1)

    def test_helpers(self):
        self.assertEqual(detect.human(512), "512 B")
        self.assertEqual(detect.human(2048), "2.0 KB")
        self.assertEqual(detect.mask("abc"), "****")


class ReportTests(Base):
    def test_json_report_structure(self):
        findings = self.run_detect(synth.demo_capture())
        data = json.loads(report.render_json(self.analysis, findings))
        self.assertEqual(data["summary"]["packets"], self.analysis.packets)
        self.assertEqual(len(data["findings"]), len(findings))
        self.assertIn("secure.example", data["summary"]["tls_server_names"])
        self.assertIn("www.example", data["summary"]["http_hosts"])

    def test_html_escapes_attacker_controlled_text(self):
        b = synth.Builder()
        synth.http_get(b, host="<script>alert(1)</script>.example", path="/<img/onerror=alert(2)>", ua="<b>ua</b>")
        b.dns_query(CLIENT, synth.RESOLVER, "<svg onload=alert(3)>.example")
        findings = self.run_detect(b)
        page = report.render_html(self.analysis, findings)
        for raw in ("<script>alert(1)", "<img/onerror", "<b>ua</b>", "<svg onload"):
            self.assertNotIn(raw, page)
        self.assertIn("&lt;script&gt;", page)
        self.assertEqual(page.lower().count("<script"), 0)
        self.assertIn("default-src 'none'", page)

    def test_text_report_mentions_key_facts(self):
        text = report.render_text(analysis := self.analysis_of_demo(), detect.detect_all(analysis))
        for part in ("Packets  :", "Top talkers:", "Findings (", "cleartext-credentials"):
            self.assertIn(part, text)

    def analysis_of_demo(self):
        self.run_detect(synth.demo_capture())
        return self.analysis

    def test_dns_and_http_logs(self):
        a = self.analysis_of_demo()
        names = {n["name"]: n for n in report.dns_log(a)}
        self.assertIn("flag{synthetic_dns_demo}.ctf.example", names)
        self.assertTrue(any(r["host"] == "shop.example" and r["user_agent"].startswith("sqlmap") for r in report.http_log(a)))


if __name__ == "__main__":
    unittest.main()
