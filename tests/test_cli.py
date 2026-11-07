import gzip
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from pcaplens import cli, synth

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class CliBase(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = tmp.name
        self.demo = self.path("demo.pcap")
        synth.demo_capture().write_pcap(self.demo)

    def path(self, name):
        return os.path.join(self.dir, name)

    def run_cli(self, *argv):
        out = io.StringIO()
        with mock.patch("sys.stderr", io.StringIO()) as err:
            code = cli.main(list(argv), out=out)
        return code, out.getvalue(), err.getvalue()


class SampleAndDetectTests(CliBase):
    def test_sample_formats(self):
        for fmt in ("pcap", "pcapng"):
            p = self.path("s." + fmt)
            code, out, _ = self.run_cli("sample", p, "--format", fmt)
            self.assertEqual(code, 0)
            self.assertIn("made up", out)
            self.assertEqual(self.run_cli("summary", p)[0], 0)

    def test_detect_demo_exit_code_and_text(self):
        code, out, _ = self.run_cli("detect", self.demo)
        self.assertEqual(code, 1)
        for rule in ("port-scan", "dns-tunneling", "arp-spoofing", "cleartext-credentials", "beaconing"):
            self.assertIn(rule, out)

    def test_detect_json_and_min_severity(self):
        code, out, _ = self.run_cli("detect", self.demo, "--format", "json", "--min-severity", "HIGH")
        data = json.loads(out)
        self.assertEqual(code, 1)
        self.assertTrue(data["findings"])
        self.assertTrue(all(f["severity"] == "HIGH" for f in data["findings"]))

    def test_threshold_override(self):
        _, base, _ = self.run_cli("detect", self.demo, "--format", "json")
        _, tuned, _ = self.run_cli("detect", self.demo, "--format", "json", "--threshold", "exfil_bytes=100000", "--threshold", "scan_ports=100")
        rules = lambda text: {f["rule"] for f in json.loads(text)["findings"]}
        self.assertNotIn("large-upload", rules(base))
        self.assertIn("large-upload", rules(tuned))
        self.assertNotIn("port-scan", rules(tuned))

    def test_bad_thresholds(self):
        self.assertEqual(self.run_cli("detect", self.demo, "--threshold", "scan_ports")[0], 2)
        self.assertEqual(self.run_cli("detect", self.demo, "--threshold", "bogus=1")[0], 2)
        self.assertEqual(self.run_cli("detect", self.demo, "--threshold", "scan_ports=abc")[0], 2)

    def test_clean_capture_exit_zero(self):
        b = synth.Builder()
        synth.normal_browsing(b)
        p = self.path("clean.pcap")
        b.write_pcap(p)
        code, out, _ = self.run_cli("detect", p)
        self.assertEqual(code, 0)
        self.assertIn("Findings (0)", out)


class ViewTests(CliBase):
    def test_summary_text_and_json(self):
        code, out, _ = self.run_cli("summary", self.demo)
        self.assertIn("Protocols:", out)
        self.assertNotIn("Findings", out)
        data = json.loads(self.run_cli("summary", self.demo, "--json")[1])
        self.assertEqual(data["format"], "pcap")
        self.assertGreater(data["packets"], 100)

    def test_flows_and_streams(self):
        _, out, _ = self.run_cli("flows", self.demo, "--proto", "udp", "--top", "3")
        self.assertIn("UDP", out)
        self.assertNotIn(" TCP ", out)
        _, out, _ = self.run_cli("streams", self.demo)
        self.assertIn("203.0.113.10:80", out)

    def test_stream_directions_and_hex(self):
        _, out, _ = self.run_cli("stream", self.demo, "0", "--direction", "c2s")
        self.assertIn("GET /index.html HTTP/1.1", out)
        self.assertNotIn("=== s2c", out)
        _, out, _ = self.run_cli("stream", self.demo, "0", "--direction", "s2c")
        self.assertIn("<html>hello</html>", out)
        _, out, _ = self.run_cli("stream", self.demo, "0", "--hex")
        self.assertIn("00000000", out)

    def test_stream_errors(self):
        self.assertEqual(self.run_cli("stream", self.demo, "99999")[0], 2)
        udp_id = [f.id for f in __import__("pcaplens.analyze", fromlist=["x"]).analyze_file(self.demo).flow_list if f.proto == "UDP"][0]
        self.assertEqual(self.run_cli("stream", self.demo, str(udp_id))[0], 2)

    def test_dns_and_http_listing(self):
        _, out, _ = self.run_cli("dns", self.demo, "--top", "100")
        self.assertIn("ctf.example", out)
        self.assertIn("NXDOMAIN", out)
        _, out, _ = self.run_cli("http", self.demo)
        self.assertIn("http://shop.example/index.php", out)

    def test_creds_masks_passwords(self):
        code, out, _ = self.run_cli("creds", self.demo)
        self.assertEqual(code, 1)
        self.assertIn("user=alice password=***", out)
        for secret in ("fake-demo-pass-1", "fake-basic-pass-2", "fake-ftp-pass-3"):
            self.assertNotIn(secret, out)
        b = synth.Builder()
        synth.normal_browsing(b)
        b.write_pcap(self.path("c.pcap"))
        self.assertEqual(self.run_cli("creds", self.path("c.pcap"))[0], 0)


class GrepTests(CliBase):
    def test_flags_plain_dns_and_base64(self):
        code, out, _ = self.run_cli("grep", self.demo, "--flags")
        self.assertEqual(code, 0)
        self.assertIn("flag{synthetic_plain_demo}", out)
        self.assertIn("flag{synthetic_dns_demo}", out)
        self.assertNotIn("flag{synthetic_base64_demo}", out)
        _, out, _ = self.run_cli("grep", self.demo, "--flags", "--base64")
        self.assertIn("flag{synthetic_base64_demo}", out)
        self.assertIn("base64", out)

    def test_pattern_modes(self):
        self.assertEqual(self.run_cli("grep", self.demo, "SHOP.EXAMPLE")[0], 1)
        self.assertEqual(self.run_cli("grep", self.demo, "SHOP.EXAMPLE", "-i")[0], 0)
        code, out, _ = self.run_cli("grep", self.demo, r"id=\d", "-E")
        self.assertEqual(code, 0)
        self.assertEqual(self.run_cli("grep", self.demo, "definitely-not-present-xyz")[0], 1)

    def test_pattern_is_literal_by_default(self):
        self.assertEqual(self.run_cli("grep", self.demo, "id=.")[0], 1)

    def test_missing_pattern(self):
        self.assertEqual(self.run_cli("grep", self.demo)[0], 2)


class ExtractTests(CliBase):
    def build(self):
        b = synth.Builder()
        page = b"<html>" + b"A" * 300 + b"</html>"
        synth.http_get(b, path="/a.html", body=page, cport=51000)
        synth.http_get(b, path="/zipped", body=gzip.compress(b"secret-ish text " * 20), cport=51001, ctype="text/plain",
                       extra_req="")
        resp_body = b"MZ" + b"\x00" * 100
        req = b"GET /../../evil.exe HTTP/1.1\r\nHost: files.example\r\n\r\n"
        resp = (b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"../../../tmp/pwn.sh\"\r\n"
                b"Content-Length: %d\r\n\r\n" % len(resp_body)) + resp_body
        b.tcp_session(synth.CLIENT, 51002, synth.WEB, 80, req, resp)
        gz = gzip.compress(b"hello gzip body " * 10)
        resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(gz) + gz
        b.tcp_session(synth.CLIENT, 51003, synth.WEB, 80, b"GET /gz HTTP/1.1\r\nHost: g.example\r\n\r\n", resp)
        p = self.path("ex.pcap")
        b.write_pcap(p)
        return p

    def test_extract_files_manifest_and_safety(self):
        out_dir = self.path("out")
        code, msg, _ = self.run_cli("extract", self.build(), "--out", out_dir)
        self.assertEqual(code, 0)
        self.assertIn("do not open or run", msg)
        with open(os.path.join(out_dir, "manifest.json")) as fh:
            manifest = json.load(fh)
        self.assertEqual(len(manifest), 4)
        names = set(os.listdir(out_dir)) - {"manifest.json"}
        self.assertEqual(len(names), 4)
        for name in names:                                    # only safe, generated names: no traversal, no server-chosen names
            self.assertRegex(name, r"^\d{3}_\d{2}_[0-9a-f]{12}\.(html|txt|bin)$")
        self.assertFalse(os.path.exists("/tmp/pwn.sh"))
        by_url = {m["url"]: m for m in manifest}
        self.assertTrue(by_url["http://files.example/../../evil.exe"]["looks_executable"])
        self.assertTrue(by_url["http://files.example/../../evil.exe"]["file"].endswith(".bin"))
        gz = by_url["http://g.example/gz"]
        with open(os.path.join(out_dir, gz["file"]), "rb") as fh:
            self.assertEqual(fh.read(), b"hello gzip body " * 10)
        import hashlib
        for m in manifest:
            with open(os.path.join(out_dir, m["file"]), "rb") as fh:
                self.assertEqual(hashlib.sha256(fh.read()).hexdigest(), m["sha256"])

    def test_extract_twice_is_idempotent(self):
        p, out_dir = self.build(), self.path("out")
        self.run_cli("extract", p, "--out", out_dir)
        before = sorted(os.listdir(out_dir))
        self.assertEqual(self.run_cli("extract", p, "--out", out_dir)[0], 0)
        self.assertEqual(sorted(os.listdir(out_dir)), before)


class ReportAndErrorTests(CliBase):
    def test_report_files(self):
        html_path, json_path = self.path("r.html"), self.path("r.json")
        code, out, _ = self.run_cli("report", self.demo, "--html", html_path, "--json", json_path)
        self.assertEqual(code, 0)
        with open(html_path, encoding="utf-8") as fh:
            page = fh.read()
        self.assertTrue(page.startswith("<!doctype html>"))
        self.assertNotIn("<script", page.lower())
        with open(json_path) as fh:
            self.assertTrue(json.load(fh)["findings"])

    def test_errors(self):
        self.assertEqual(self.run_cli("summary", self.path("missing.pcap"))[0], 2)
        junk = self.path("junk.pcap")
        with open(junk, "wb") as fh:
            fh.write(b"this is not a capture file at all")
        code, _, err = self.run_cli("summary", junk)
        self.assertEqual(code, 2)
        self.assertIn("not a pcap", err)

    def test_module_entry_point(self):
        r = subprocess.run([sys.executable, "-m", "pcaplens", "--version"], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0)
        self.assertIn("1.0.0", r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
