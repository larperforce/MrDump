import hashlib
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import mrdump_core as core
from mrdump_core import (
    analyze_binary,
    entropy,
    identify,
    parse_ports,
    printable_strings,
    query_osv,
    query_virustotal,
    resolve_private_targets,
    run_clamav_scan,
    scan_private_network,
    save_text_report,
    render_text_report,
)


class CoreTests(unittest.TestCase):
    def test_entropy_empty_and_uniform(self):
        self.assertEqual(entropy(b""), 0.0)
        self.assertEqual(entropy(b"A" * 100), 0.0)
        self.assertAlmostEqual(entropy(bytes(range(256))), 8.0)

    def test_identify_signatures(self):
        self.assertEqual(identify(b"MZxxxx")[0], "DOS/MZ executable or PE-like file")
        self.assertEqual(identify(b"\x7fELF\x02\x01")[0], "ELF executable/object")
        self.assertEqual(identify(b"PK\x03\x04abc")[0], "ZIP archive")
        self.assertEqual(identify(b"%PDF-1.7")[0], "PDF document")

    def test_identify_mp4(self):
        self.assertEqual(identify(b"\x00\x00\x00\x18ftypisom" )[0], "MP4 / ISO Base Media video")

    def test_large_file_is_sampled_but_hash_covers_all_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.mp4"
            content = b"\x00\x00\x00\x18ftypisom" + (b"A" * 4096)
            path.write_bytes(content)
            with mock.patch.object(core, "MAX_FILE_SIZE", 1024):
                report = analyze_binary(path)
            self.assertTrue(report.sampled)
            self.assertEqual(report.size_bytes, len(content))
            self.assertEqual(report.sha256, hashlib.sha256(content).hexdigest())
            self.assertEqual(report.file_type, "MP4 / ISO Base Media video")

    def test_identify_valid_pe_signature(self):
        sample = bytearray(256)
        sample[:2] = b"MZ"
        sample[0x3C:0x40] = (0x80).to_bytes(4, "little")
        sample[0x80:0x84] = b"PE\x00\x00"
        self.assertEqual(identify(bytes(sample))[0], "Windows PE executable")

    def test_extract_ascii_and_utf16_strings(self):
        data = b"prefix-HELLO-STRING-" + "powershell.exe -enc ABCD".encode("utf-16le")
        values = printable_strings(data)
        self.assertTrue(any(value.startswith("prefix-HELLO-STRING-") for value in values))
        self.assertIn("powershell.exe -enc ABCD", values)

    def test_analyze_text_file_and_hash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.txt"
            data = b"hello world\n" * 20
            path.write_bytes(data)
            report = analyze_binary(path)
            self.assertEqual(report.sha256, hashlib.sha256(data).hexdigest())
            self.assertEqual(report.file_type, "Unknown / raw binary")
            self.assertTrue(report.strings)
            self.assertEqual(report.score, 0)

    def test_utf16_powershell_indicator(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes("powershell.exe -enc AAAA".encode("utf-16le"))
            report = analyze_binary(path)
            self.assertTrue(any("PowerShell encoded" in item.title for item in report.findings))
            self.assertGreater(report.score, 0)

    def test_malware_heuristics_are_labeled_findings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "document.txt"
            path.write_bytes(b"powershell.exe -enc AAAA")
            report = analyze_binary(path)
            self.assertTrue(any("PowerShell encoded" in item.title for item in report.findings))
            self.assertGreater(report.score, 0)
            self.assertLessEqual(report.score, 100)

    def test_zip_metadata_detects_script_and_path_traversal(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bundle.zip"
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("../startup/payload.ps1", "Write-Output test")
                archive.writestr("docs/readme.txt", "ordinary text")
            report = analyze_binary(path)
            self.assertTrue(any("payload.ps1" in entry for entry in report.archive_entries))
            self.assertTrue(any("path-traversal" in entry for entry in report.archive_entries))
            self.assertTrue(any("script-like" in entry for entry in report.archive_entries))

    def test_zip_invalid_archive_does_not_crash(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.zip"
            path.write_bytes(b"PK\x03\x04 not a valid archive")
            report = analyze_binary(path)
            self.assertTrue(report.archive_error)

    def test_parse_ports(self):
        self.assertEqual(parse_ports("80,443,8000-8002"), [80, 443, 8000, 8001, 8002])
        self.assertEqual(len(parse_ports("1-32")), 32)
        with self.assertRaises(ValueError):
            parse_ports("0")
        with self.assertRaises(ValueError):
            parse_ports("1-33")
        with self.assertRaises(ValueError):
            parse_ports("80,,443")
        with self.assertRaises(ValueError):
            parse_ports("  ")
        with self.assertRaises(ValueError):
            parse_ports("٨٠")

    def test_private_targets(self):
        self.assertEqual(resolve_private_targets("127.0.0.1"), ["127.0.0.1"])
        self.assertEqual(resolve_private_targets("192.168.1.0/30"), ["192.168.1.1", "192.168.1.2"])
        self.assertEqual(resolve_private_targets("192.168.1.10/32"), ["192.168.1.10"])
        with self.assertRaises(ValueError):
            resolve_private_targets("8.8.8.8")
        with self.assertRaises(ValueError):
            resolve_private_targets("192.168.1.0/16")
        with self.assertRaises(ValueError):
            resolve_private_targets("2001:db8::1")

    def test_hostname_with_mixed_public_private_addresses_is_blocked(self):
        records = [
            (None, None, None, None, ("192.168.1.10", 0)),
            (None, None, None, None, ("8.8.8.8", 0)),
        ]
        with mock.patch.object(core.socket, "getaddrinfo", return_value=records):
            with self.assertRaises(ValueError):
                resolve_private_targets("mixed.example")

    def test_network_timeout_validation(self):
        with self.assertRaises(ValueError):
            scan_private_network("127.0.0.1", "80", timeout=0)
        with self.assertRaises(ValueError):
            scan_private_network("127.0.0.1", "80", timeout=6)

    def test_text_report_is_plain_text_and_contains_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"simple sample data")
            report = analyze_binary(path)
            output = save_text_report(report, Path(directory) / "reports" / "report.txt")
            text = output.read_text(encoding="utf-8")
            self.assertIn("MrDump 0.4.0", text)
            self.assertIn(report.sha256, text)
            self.assertIn("SAFETY NOTES", text)
            self.assertFalse(text.lstrip().startswith("{"))

    def test_text_report_cannot_overwrite_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            original = b"preserve this exact content"
            path.write_bytes(original)
            report = analyze_binary(path)
            with self.assertRaises(ValueError):
                save_text_report(report, path)
            self.assertEqual(path.read_bytes(), original)

    def test_text_report_refuses_existing_destination(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            target_report = Path(directory) / "existing.txt"
            path.write_bytes(b"sample")
            target_report.write_text("keep me", encoding="utf-8")
            report = analyze_binary(path)
            with self.assertRaises(ValueError):
                save_text_report(report, target_report)
            self.assertEqual(target_report.read_text(encoding="utf-8"), "keep me")

    def test_osv_query_parses_valid_response(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, size=-1):
                return b'{"vulns":[{"id":"TEST-2026-0001","summary":"demo"}]}'

        with mock.patch.object(core.urllib.request, "urlopen", return_value=FakeResponse()):
            result = query_osv("demo-package", "1.2.3", "PyPI")
        self.assertEqual(result[0]["id"], "TEST-2026-0001")

    def test_osv_rejects_non_object_response(self):
        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def read(self, size=-1):
                return b'[]'

        with mock.patch.object(core.urllib.request, "urlopen", return_value=FakeResponse()):
            with self.assertRaises(RuntimeError):
                query_osv("demo-package", "1.2.3", "PyPI")

    def test_virustotal_requires_key_and_valid_hash(self):
        with self.assertRaises(ValueError):
            query_virustotal("not-a-hash", api_key="example")
        with self.assertRaises(ValueError):
            query_virustotal("a" * 64, api_key="")


    def test_scan_private_network_finds_listening_loopback_port(self):
        import socket

        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.bind(("127.0.0.1", 0))
            listener.listen(1)
            port = listener.getsockname()[1]
            hosts, opened = scan_private_network("127.0.0.1", str(port), timeout=0.3)
            self.assertEqual(hosts, ["127.0.0.1"])
            self.assertIn(("127.0.0.1", port), opened)
        finally:
            listener.close()

    def test_clamav_unavailable_is_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"sample")
            with mock.patch.object(core.shutil, "which", return_value=None):
                result = run_clamav_scan(path)
            self.assertEqual(result.status, "UNAVAILABLE")

    def test_clamav_invocation_does_not_use_shell(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.bin"
            path.write_bytes(b"sample")
            completed = mock.Mock(returncode=0, stdout="sample: OK", stderr="")
            with mock.patch.object(core.shutil, "which", return_value="/usr/bin/clamscan"):
                with mock.patch.object(core.subprocess, "run", return_value=completed) as run:
                    result = run_clamav_scan(path)
            self.assertEqual(result.status, "CLEAN")
            self.assertFalse(run.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
