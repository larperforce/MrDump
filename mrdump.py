from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from mrdump_core import (
    VERSION,
    analyze_binary,
    query_osv,
    query_virustotal,
    run_clamav_scan,
    save_text_report,
    scan_private_network,
)


def hexdump(data: bytes, limit: int = 512) -> str:
    lines: list[str] = []
    for offset in range(0, min(len(data), limit), 16):
        chunk = data[offset:offset + 16]
        hx = " ".join(f"{byte:02X}" for byte in chunk)
        asc = "".join(chr(byte) if 32 <= byte < 127 else "." for byte in chunk)
        lines.append(f"{offset:08X}  {hx:<47}  |{asc}|")
    if len(data) > limit:
        lines.append(f"... displayed sample capped at {limit} bytes ...")
    return "\n".join(lines) or "(empty file)"


def suggested_report_path(target: Path) -> Path:
    base = target.with_name(f"{target.stem}.mrdump-report.txt")
    if not base.exists():
        return base
    for number in range(2, 1000):
        candidate = target.with_name(f"{target.stem}.mrdump-report-{number}.txt")
        if not candidate.exists():
            return candidate
    return target.with_name(f"{target.stem}.mrdump-report-{target.stat().st_mtime_ns}.txt")


def _record_external(report, engine: str, status: str, detail: str = "") -> None:
    report.external_scans.append({"engine": engine, "status": status, "detail": detail})


def run_tui(target: Path, report) -> None:
    try:
        from textual.app import App, ComposeResult
        from textual.containers import Vertical, Horizontal
        from textual.widgets import Static, TabbedContent, TabPane, Input, Button
        from textual.binding import Binding
    except ImportError as exc:
        raise SystemExit(
            "Textual is required for the interactive MrDump interface. Run install.bat first."
        ) from exc

    class MrDumpApp(App):
        TITLE = "MrDump"
        SUB_TITLE = f"by aymen  |  Defensive Security Inspection Suite  |  v{VERSION}"
        CSS = """
        Screen {
            background: #101014;
            color: #d9e0e7;
        }
        #frame {
            margin: 1 2;
            height: 1fr;
            border: round #566675;
            padding: 0 1;
        }
        #topline {
            height: 3;
            border: round #3d7074;
            padding: 0 1;
            color: #75d2c7;
            content-align: center middle;
            text-style: bold;
        }
        #hero {
            height: 3;
            content-align: center middle;
            color: #e9edf2;
            text-style: bold;
        }
        #tagline {
            height: 1;
            content-align: center middle;
            color: #d9aa62;
        }
        #pathline {
            height: 2;
            content-align: center middle;
            color: #8dc5c1;
        }
        #summary {
            height: 7;
            width: 1fr;
            border: round #68717c;
            padding: 1;
            margin: 1 0;
        }
        #tabs {
            height: 1fr;
            margin: 0 1;
        }
        TabbedContent {
            height: 1fr;
        }
        TabPane {
            padding: 1 2;
            overflow-y: auto;
        }
        Static {
            width: 1fr;
        }
        Input {
            margin: 1 0;
            border: round #566675;
            width: 1fr;
        }
        Button {
            margin: 1 1 1 0;
            min-width: 22;
        }
        #footer {
            height: 2;
            border: round #566675;
            content-align: center middle;
            color: #d9aa62;
            margin-top: 1;
        }
        .section-title {
            color: #75d2c7;
            text-style: bold;
        }
        .warning {
            color: #e1b46b;
        }
        """
        BINDINGS = [
            Binding("q", "quit", "Quit"),
            Binding("escape", "quit", "Quit"),
        ]

        def __init__(self, target_path: Path, binary_report):
            super().__init__()
            self.target = target_path
            self.report = binary_report
            self.report_suggestion = suggested_report_path(target_path)

        def compose(self) -> ComposeResult:
            r = self.report
            sample_flag = "SAMPLED" if r.sampled else "FULL"
            summary = (
                f"File: {self.target.name}\n"
                f"Size: {r.size_bytes:,} bytes  |  Mode: {sample_flag}\n"
                f"Type: {r.file_type}\n"
                f"Entropy: {r.entropy:.4f} bits/byte  |  Heuristic score: {r.score}/100\n"
                f"SHA-256: {r.sha256[:48]}…"
            )
            findings = "\n\n".join(
                f"[{item.severity}] {item.title}\n  {item.detail}"
                for item in r.findings
            ) or "No configured indicators matched. This does not prove safety."
            with Vertical(id="frame"):
                yield Static(
                    f"MrDump {VERSION}  |  BY AYMEN  |  LOCAL ANALYSIS  |  DEFENSIVE TOOLS",
                    id="topline",
                )
                yield Static("MrDump", id="hero")
                yield Static(
                    "Malware Triage  •  PE / ZIP Analysis  •  Threat Intelligence  •  Network Visibility",
                    id="tagline",
                )
                yield Static(f"TARGET  •  {self.target}", id="pathline")
                yield Static(summary, id="summary", markup=False)

                with TabbedContent(initial="general", id="tabs"):
                    with TabPane("General", id="general"):
                        yield Static(
                            f"TARGET       {self.target}\n"
                            f"FILE TYPE    {r.file_type}\n"
                            f"FORMAT       {r.details}\n"
                            f"SHA-256      {r.sha256}\n"
                            f"SIZE         {r.size_bytes:,} bytes\n"
                            f"ENTROPY      {r.entropy:.4f} / 8.0000\n"
                            f"ANALYSIS     {'SAMPLED (first + last parts)' if r.sampled else 'FULL FILE'}\n\n"
                            "LOCAL / READ-ONLY: MrDump does not execute or modify the inspected file.\n"
                            "The malware score is a heuristic indicator, not a probability or antivirus verdict.",
                            markup=False,
                        )
                    with TabPane("Static", id="static"):
                        yield Static(
                            f"STATIC TRIAGE\n\n"
                            f"Signature: {r.data[:16].hex(' ').upper() or '(empty)'}\n"
                            f"Null bytes in analyzed data: {r.data.count(bytes([0])):,}\n"
                            f"Unique byte values: {len(set(r.data))}\n"
                            f"High-entropy indicator: {'YES' if r.entropy >= 7.2 else 'NO'}\n"
                            f"Extracted strings: {len(r.strings)}\n"
                            f"ZIP notable entries: {len(r.archive_entries)}\n"
                            f"PE parser status: {r.pe_error or 'No parser error reported.'}\n\n"
                            + ("NOTE: This large file was sampled. Static results apply to sampled regions; SHA-256 covers the complete file.\n\n" if r.sampled else "")
                            + "Entropy and strings are clues only; both benign and malicious files can trigger them.",
                            markup=False,
                        )
                    with TabPane("Strings", id="strings"):
                        yield Static(
                            "ASCII + UTF-16LE STRINGS\n\n" + ("\n".join(r.strings[:600]) or "(no printable strings found)"),
                            markup=False,
                        )
                    with TabPane("Hexdump", id="hexdump"):
                        yield Static(hexdump(r.data), markup=False)
                    with TabPane("Malware", id="malware"):
                        yield Static(
                            f"MALWARE TRIAGE — STATIC HEURISTICS ONLY\n\n"
                            f"Heuristic score: {r.score}/100 (not a probability)\n\n"
                            f"FINDINGS\n{findings}\n\n"
                            "A low score does not prove safety; a high score does not prove infection.",
                            markup=False,
                        )
                    with TabPane("PE Analysis", id="pe_analysis"):
                        yield Static(
                            f"PORTABLE EXECUTABLE ANALYSIS\n\n"
                            f"File type: {r.file_type}\n"
                            f"Validation: {r.details}\n\n"
                            "SECTIONS\n" + ("\n".join(r.pe_sections) or "No PE sections available.") +
                            "\n\nSELECTED IMPORTS\n" + ("\n".join(r.imports[:200]) or "No imports extracted.") +
                            "\n\n" + (r.pe_error or "PE parser status: no error reported."),
                            markup=False,
                        )
                    with TabPane("ZIP Analysis", id="zip_analysis"):
                        yield Static(
                            "ZIP METADATA INSPECTION — MEMBERS ARE NEVER EXTRACTED\n\n"
                            f"Notable entries: {len(r.archive_entries)}\n\n" +
                            ("\n".join(r.archive_entries) or "No notable entries found, or this file is not a ZIP archive.") +
                            "\n\n" + (r.archive_error or "Archive parser status: no error reported."),
                            markup=False,
                        )
                    with TabPane("ClamAV", id="clamav"):
                        yield Static(
                            "OPTIONAL LOCAL ANTIVIRUS ENGINE\n\n"
                            "MrDump can call the installed ClamAV command-line scanner (clamscan).\n"
                            "Install ClamAV and update its signatures before scanning. The target is not executed by MrDump.",
                            markup=False,
                        )
                        yield Button("RUN CLAMAV LOCAL SCAN", id="run_clamav", variant="warning")
                        yield Static("No ClamAV scan has been started.", id="clamav_result", markup=False)
                    with TabPane("Threat Intel", id="threatintel"):
                        yield Static(
                            "VIRUSTOTAL HASH REPUTATION\n\n"
                            "Only the SHA-256 hash is sent. The file itself is not uploaded.\n"
                            "A VirusTotal API key in VT_API_KEY is required. Avoid querying hashes of confidential files.\n\n"
                            f"SHA-256: {r.sha256}",
                            markup=False,
                        )
                        yield Button("LOOK UP SHA-256", id="check_vt", variant="primary")
                        yield Static("Waiting for a VirusTotal lookup.", id="vt_result", markup=False)
                    with TabPane("Vulnerabilities", id="vulnerabilities"):
                        yield Static(
                            "OSV PACKAGE VERSION LOOKUP\n\n"
                            "Check an exact package, version, and ecosystem against OSV.\n"
                            "This is not a full scan of all installed software on the computer.",
                            markup=False,
                        )
                        with Horizontal():
                            yield Input(placeholder="Package name (e.g. requests)", id="pkg_name")
                            yield Input(value="2.31.0", placeholder="Version", id="pkg_version")
                        with Horizontal():
                            yield Input(value="PyPI", placeholder="Ecosystem (PyPI, npm, Maven...)", id="pkg_ecosystem")
                            yield Button("CHECK OSV", id="check_osv", variant="primary")
                        yield Static("Enter package, version, and ecosystem.", id="vuln_result", markup=False)
                    with TabPane("Network", id="network"):
                        yield Static(
                            "TCP CONNECT SCAN — AUTHORIZED PRIVATE NETWORKS ONLY\n\n"
                            "Only private, loopback, and link-local IPv4 targets are accepted. Public targets are blocked.\n"
                            "No exploitation, credential attempts, brute force, or banner grabbing is performed.",
                            markup=False,
                        )
                        yield Input(placeholder="Private target IP / CIDR / hostname (e.g. 192.168.1.10)", id="net_target")
                        yield Input(value="22,80,443,445,3389,8080,8443", placeholder="TCP ports (e.g. 22,80,443 or 8000-8010)", id="net_ports")
                        yield Button("I AM AUTHORIZED — START SCAN", id="start_scan", variant="warning")
                        yield Static("No network scan has been started.", id="net_result", markup=False)
                    with TabPane("Reports", id="reports"):
                        yield Static(
                            "PLAIN-TEXT REPORT EXPORT\n\n"
                            "MrDump exports a readable .txt report. No JSON report is generated.\n"
                            "Existing files are never overwritten, and the inspected file is protected.",
                            markup=False,
                        )
                        yield Input(value=str(self.report_suggestion), placeholder="Full path for .txt report", id="report_path")
                        yield Button("SAVE TEXT REPORT", id="save_report", variant="primary")
                        yield Static("The report has not been saved yet.", id="report_result", markup=False)
                    with TabPane("Security", id="security"):
                        yield Static(
                            "MRDUMP SECURITY BOUNDARIES\n\n"
                            "[OK] Target files are read as data; MrDump does not execute them.\n"
                            "[OK] The inspected file is not modified by static analysis.\n"
                            "[OK] ZIP members are checked from metadata only and are never extracted.\n"
                            "[OK] Text report export refuses to overwrite the inspected target or any existing file.\n"
                            "[OK] VirusTotal receives a SHA-256 hash only; the file is not uploaded.\n"
                            "[OK] Network scans are limited to private / loopback / link-local IPv4 targets.\n\n"
                            "ANALYSIS LIMITS\n"
                            "Static heuristics can miss threats or flag legitimate software.\n"
                            "ClamAV and online services require their own installation, signatures, network, or API access.\n"
                            "A clean result is not a 100% guarantee. Do not use MrDump as your only security control.",
                            markup=False,
                        )
                yield Static("← / → Switch tabs  •  Tab / Shift+Tab Move focus  •  Q Quit", id="footer")

        async def on_button_pressed(self, event: Button.Pressed) -> None:
            button_id = event.button.id
            if button_id == "run_clamav":
                output = self.query_one("#clamav_result", Static)
                output.update("Running local ClamAV scan. Please wait…")
                result = await asyncio.to_thread(run_clamav_scan, self.target)
                self.report.external_scans.append({
                    "engine": result.engine,
                    "status": result.status,
                    "output": result.output,
                    "detail": f"Exit code: {result.returncode}; duration: {result.duration_seconds:.2f}s",
                })
                output.update(
                    f"Engine: {result.engine}\nStatus: {result.status}\n"
                    f"Duration: {result.duration_seconds:.2f}s\nExit code: {result.returncode}\n\n{result.output}"
                )

            elif button_id == "check_osv":
                package = self.query_one("#pkg_name", Input).value.strip()
                version = self.query_one("#pkg_version", Input).value.strip()
                ecosystem = self.query_one("#pkg_ecosystem", Input).value.strip()
                output = self.query_one("#vuln_result", Static)
                output.update("Checking OSV online…")
                try:
                    vulns = await asyncio.to_thread(query_osv, package, version, ecosystem)
                    if not vulns:
                        detail = "No matching OSV records were returned. This is not proof the package is vulnerability-free."
                    else:
                        lines = [f"{len(vulns)} matching advisory record(s):"]
                        for item in vulns[:30]:
                            aliases = ", ".join(item.get("aliases", [])[:5])
                            lines.append(
                                f"\n{item.get('id', 'Unknown ID')}  {aliases}\n"
                                f"{item.get('summary', 'No summary supplied')}"
                            )
                        if len(vulns) > 30:
                            lines.append(f"\n… {len(vulns) - 30} more records omitted")
                        detail = "\n".join(lines)
                    self.report.external_scans.append({"engine": "OSV", "status": f"{len(vulns)} result(s)", "detail": f"{package} {version} ({ecosystem})\n{detail}"})
                    output.update(detail)
                except Exception as exc:
                    output.update(f"OSV lookup failed: {exc}")

            elif button_id == "check_vt":
                output = self.query_one("#vt_result", Static)
                output.update("Contacting VirusTotal with the SHA-256 hash only…")
                try:
                    result = await asyncio.to_thread(query_virustotal, self.report.sha256)
                    if result.get("not_found"):
                        detail = "No VirusTotal report exists for this hash."
                        self.report.external_scans.append({"engine": "VirusTotal", "status": "NOT FOUND", "detail": detail})
                    else:
                        attrs = result.get("data", {}).get("attributes", {})
                        stats = attrs.get("last_analysis_stats", {})
                        detection_results = attrs.get("last_analysis_results", {})
                        lines = [
                            "VIRUSTOTAL REPORT",
                            f"Malicious: {stats.get('malicious', 0)}",
                            f"Suspicious: {stats.get('suspicious', 0)}",
                            f"Undetected: {stats.get('undetected', 0)}",
                            f"Harmless: {stats.get('harmless', 0)}",
                            f"Reputation: {attrs.get('reputation', 'n/a')}",
                            f"Last analysis: {attrs.get('last_analysis_date', 'n/a')}",
                            f"Names: {', '.join(attrs.get('names', [])[:8]) or 'n/a'}",
                            f"Type: {attrs.get('type_description', 'n/a')}",
                            "",
                            "ENGINE RESULTS (first 25)",
                        ]
                        for engine, item in list(detection_results.items())[:25]:
                            lines.append(
                                f"{engine}: {item.get('category', 'unknown')} — {item.get('result') or 'no label'}"
                            )
                        lines.append("\nVendor results are not a definitive verdict.")
                        detail = "\n".join(lines)
                        self.report.external_scans.append({"engine": "VirusTotal", "status": f"{stats.get('malicious', 0)} malicious / {stats.get('suspicious', 0)} suspicious", "detail": detail})
                    output.update(detail)
                except Exception as exc:
                    output.update(f"Threat intelligence lookup failed: {exc}")

            elif button_id == "start_scan":
                target_value = self.query_one("#net_target", Input).value.strip()
                ports = self.query_one("#net_ports", Input).value.strip()
                output = self.query_one("#net_result", Static)
                output.update("Scanning authorized private target(s)…")
                try:
                    hosts, opened = await asyncio.to_thread(scan_private_network, target_value, ports)
                    lines = [f"Completed. Hosts checked: {len(hosts)}", f"Ports configured: {ports}", ""]
                    if opened:
                        lines.append("OPEN TCP PORTS")
                        lines.extend(f"{host}:{port}" for host, port in opened)
                    else:
                        lines.append("No TCP connection succeeded. Ports may be closed, filtered, or unreachable.")
                    detail = "\n".join(lines)
                    self.report.external_scans.append({"engine": "Private TCP scan", "status": "COMPLETED", "detail": detail})
                    output.update(detail)
                except Exception as exc:
                    output.update(f"Network scan blocked/failed: {exc}")

            elif button_id == "save_report":
                raw_path = self.query_one("#report_path", Input).value.strip().strip('"').strip("'")
                output = self.query_one("#report_result", Static)
                try:
                    saved = await asyncio.to_thread(save_text_report, self.report, Path(raw_path))
                    output.update(f"Report saved successfully:\n{saved}\n\nExisting files were not overwritten.")
                except Exception as exc:
                    output.update(f"Report was not saved:\n{exc}")

    MrDumpApp(target, report).run()


def main() -> int:
    parser = argparse.ArgumentParser(description="MrDump — interactive defensive security inspection suite")
    parser.add_argument("target", nargs="?", help="local file to inspect (read-only)")
    parser.add_argument("--version", action="version", version=f"MrDump {VERSION}")
    args = parser.parse_args()

    raw_target = args.target
    if raw_target is None:
        raw_target = input("Enter full path to the file to inspect: ")
    raw_target = raw_target.strip().strip('"').strip("'")
    if not raw_target:
        print("[MrDump] No file path was entered.")
        return 2

    target = Path(raw_target).expanduser()
    try:
        report = analyze_binary(target)
        run_tui(target.resolve(), report)
        return 0
    except (ValueError, OSError) as exc:
        print(f"\n[MrDump error] {exc}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
