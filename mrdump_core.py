from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import os
import re
import shutil
import socket
import subprocess
import urllib.error
import urllib.request
import zipfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from time import monotonic
from typing import Any

VERSION = "0.4.0"
MAX_FILE_SIZE = 128 * 1024 * 1024
MAX_STRINGS = 10_000
MAX_STRING_LENGTH = 500
MAX_ARCHIVE_ENTRIES = 2_000
MAX_ARCHIVE_UNCOMPRESSED = 512 * 1024 * 1024
MAX_ARCHIVE_RATIO = 200
MAX_NETWORK_HOSTS = 256
MAX_NETWORK_PORTS = 64
MAX_NETWORK_JOBS = 4_096
ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(item)
    for item in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
    )
)


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    points: int = 0


@dataclass
class BinaryReport:
    path: Path
    data: bytes = field(repr=False)
    size_bytes: int = 0
    sampled: bool = False
    file_type: str = ""
    details: str = ""
    sha256: str = ""
    entropy: float = 0.0
    strings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    pe_sections: list[str] = field(default_factory=list)
    imports: list[str] = field(default_factory=list)
    pe_error: str = ""
    archive_entries: list[str] = field(default_factory=list)
    archive_error: str = ""
    external_scans: list[dict[str, Any]] = field(default_factory=list)
    score: int = 0
    analyzed_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ScannerResult:
    engine: str
    status: str
    output: str
    returncode: int | None = None
    duration_seconds: float = 0.0


def read_target_details(path: Path) -> tuple[bytes, int, bool, str]:
    """Return bounded analysis bytes, real size, sampling flag, and full-file SHA-256.

    Files up to MAX_FILE_SIZE are read completely. Larger files are sampled from
    their beginning and end while SHA-256 is calculated by streaming the entire
    file. The target is never executed or modified.
    """
    path = Path(path).expanduser()
    try:
        if not path.is_file():
            raise ValueError(f"Target is not a regular file: {path}")
        before = path.stat()
        size = before.st_size
        if size <= MAX_FILE_SIZE:
            with path.open("rb") as handle:
                data = handle.read(MAX_FILE_SIZE + 1)
            if len(data) != size or len(data) > MAX_FILE_SIZE:
                raise ValueError("Target changed while being read; try again")
            digest = hashlib.sha256(data).hexdigest()
            sampled = False
        else:
            half = (MAX_FILE_SIZE - 128) // 2
            with path.open("rb") as handle:
                head = handle.read(half)
                handle.seek(max(0, size - half))
                tail = handle.read(half)
                handle.seek(0)
                hasher = hashlib.sha256()
                while True:
                    block = handle.read(1024 * 1024)
                    if not block:
                        break
                    hasher.update(block)
            data = head + b"\n[MRDUMP SAMPLE GAP]\n" + tail
            digest = hasher.hexdigest()
            sampled = True
        after = path.stat()
        if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
            raise ValueError("Target changed during analysis; no reliable report was produced")
        return data, size, sampled, digest
    except OSError as exc:
        raise ValueError(f"Cannot read target: {exc}") from exc


def read_target(path: Path) -> bytes:
    """Compatibility helper returning the bounded bytes used for static inspection."""
    return read_target_details(path)[0]


def printable_strings(data: bytes, min_length: int = 4) -> list[str]:
    """Extract bounded ASCII and UTF-16LE/BE strings without decoding the whole file."""
    if min_length < 1 or min_length > 100:
        raise ValueError("min_length must be between 1 and 100")
    patterns = (
        (re.compile(rb"[ -~]{" + str(min_length).encode("ascii") + rb",}"), "ascii"),
        (re.compile(rb"(?:[ -~]\x00){" + str(min_length).encode("ascii") + rb",}"), "utf-16le"),
    )
    found: list[str] = []
    seen: set[str] = set()
    for pattern, encoding in patterns:
        for match in pattern.finditer(data):
            try:
                value = match.group(0).decode(encoding, errors="replace")
            except LookupError:  # pragma: no cover - fixed encodings above
                continue
            value = value[:MAX_STRING_LENGTH].strip()
            if value and value not in seen:
                seen.add(value)
                found.append(value)
                if len(found) >= MAX_STRINGS:
                    return found
    return found


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = len(data)
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def identify(data: bytes) -> tuple[str, str]:
    if data.startswith(b"\x7fELF"):
        if len(data) < 6:
            return "ELF executable/object", "ELF signature; truncated identification header"
        bits = {1: "32-bit", 2: "64-bit"}.get(data[4], "unknown class")
        endian = {1: "little-endian", 2: "big-endian"}.get(data[5], "unknown byte order")
        return "ELF executable/object", f"{bits}, {endian}"
    if data.startswith(b"MZ"):
        if len(data) >= 0x40:
            pe_offset = int.from_bytes(data[0x3C:0x40], "little")
            if 0x40 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
                return "Windows PE executable", f"Valid PE signature at offset 0x{pe_offset:X}"
        return "DOS/MZ executable or PE-like file", "MZ header detected; PE signature not verified"
    signatures = (
        (b"PK\x03\x04", "ZIP archive", "ZIP local-file header"),
        (b"\x1f\x8b", "GZIP compressed data", "GZIP signature"),
        (b"%PDF-", "PDF document", "PDF header"),
        (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE compound document", "OLE/CFB signature"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive", "7z signature"),
        (b"Rar!\x1a\x07", "RAR archive", "RAR signature"),
        (b"SQLite format 3\x00", "SQLite database", "SQLite header"),
        (b"\x89PNG\r\n\x1a\n", "PNG image", "PNG signature"),
        (b"GIF87a", "GIF image", "GIF87a signature"),
        (b"GIF89a", "GIF image", "GIF89a signature"),
        (b"\xff\xd8\xff", "JPEG image", "JPEG signature"),
    )
    for magic, file_type, details in signatures:
        if data.startswith(magic):
            return file_type, details
    if len(data) >= 12 and data[4:8] == b"ftyp":
        brand = data[8:12].decode("ascii", errors="replace")
        return "MP4 / ISO Base Media video", f"MP4-compatible container; brand={brand}"
    return "Unknown / raw binary", "No recognized signature"


# Intentionally conservative rules: findings are investigative leads, not verdicts.
SUSPICIOUS_STRINGS: list[tuple[str, re.Pattern[str], int]] = [
    (
        "PowerShell encoded command",
        re.compile(r"powershell(?:\.exe)?\s+[^\r\n]{0,160}-(?:enc|encodedcommand)\b", re.I),
        12,
    ),
    (
        "PowerShell download/execute pattern",
        re.compile(r"(?:downloadstring|downloadfile|invoke-webrequest|iwr)\s*.{0,100}(?:https?://|\$\w+)|\biex\s*\(\s*\(?\s*new-object", re.I),
        15,
    ),
    ("Windows script host", re.compile(r"\b(?:wscript|cscript)\.exe\b", re.I), 5),
    (
        "Living-off-the-land utility",
        re.compile(r"\b(?:certutil|bitsadmin|mshta|regsvr32|rundll32)\.exe\b", re.I),
        5,
    ),
    ("Credential theft indicator", re.compile(r"\b(?:mimikatz|sekurlsa|lsass\.exe)\b", re.I), 12),
    (
        "Persistence registry path",
        re.compile(r"software\\microsoft\\windows\\currentversion\\run", re.I),
        8,
    ),
    ("Scheduled task creation", re.compile(r"\bschtasks(?:\.exe)?\s+/create\b", re.I), 8),
    ("Service creation command", re.compile(r"\bsc(?:\.exe)?\s+create\b", re.I), 8),
    (
        "Shadow-copy deletion command",
        re.compile(r"\b(?:vssadmin\s+delete\s+shadows|wmic\s+shadowcopy\s+delete)\b", re.I),
        16,
    ),
    (
        "Linux download-and-execute pattern",
        re.compile(r"\b(?:curl|wget)\b[^\r\n]{0,180}\|\s*(?:sh|bash)\b", re.I),
        12,
    ),
    ("Potential reverse-shell primitive", re.compile(r"/dev/tcp/|\bnc\s+-e\s+/bin/(?:sh|bash)", re.I), 12),
    (
        "SSH authorized_keys modification",
        re.compile(r"authorized_keys", re.I),
        4,
    ),
]

SUSPICIOUS_APIS: dict[str, tuple[str, int]] = {
    "CreateRemoteThread": ("Remote thread creation (can be used for injection)", 14),
    "WriteProcessMemory": ("Cross-process memory write (can be used for injection)", 14),
    "VirtualAllocEx": ("Remote process memory allocation", 10),
    "NtWriteVirtualMemory": ("Native cross-process memory write", 14),
    "QueueUserAPC": ("APC injection-related API", 8),
    "SetWindowsHookExA": ("Windows hook API (may be used for input monitoring)", 6),
    "SetWindowsHookExW": ("Windows hook API (may be used for input monitoring)", 6),
    "GetAsyncKeyState": ("Keyboard-state API (may be used for key monitoring)", 5),
    "WinHttpOpen": ("HTTP communications capability", 2),
    "InternetOpenA": ("WinINet communications capability", 2),
    "InternetOpenW": ("WinINet communications capability", 2),
    "MiniDumpWriteDump": ("Process memory dump capability", 10),
    "CryptUnprotectData": ("Windows data decryption capability", 5),
}

EXECUTABLE_SUFFIXES = {".exe", ".dll", ".sys", ".ocx", ".scr", ".cpl"}
SCRIPT_SUFFIXES = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".hta", ".sh", ".py"}
ARCHIVE_SUFFIXES = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
DANGEROUS_ARCHIVE_SUFFIXES = EXECUTABLE_SUFFIXES | SCRIPT_SUFFIXES | {".msi", ".lnk", ".iso", ".img"}


def _inspect_zip(data: bytes, report: BinaryReport) -> int:
    """Inspect ZIP central-directory metadata only. Never extract archive members."""
    score = 0
    try:
        import io

        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            infos = archive.infolist()
            total_uncompressed = sum(max(0, info.file_size) for info in infos)
            if len(infos) > MAX_ARCHIVE_ENTRIES:
                report.archive_error = (
                    f"Archive contains {len(infos):,} entries; detailed listing capped at {MAX_ARCHIVE_ENTRIES:,}."
                )
                infos = infos[:MAX_ARCHIVE_ENTRIES]
            if total_uncompressed > MAX_ARCHIVE_UNCOMPRESSED:
                report.findings.append(
                    Finding(
                        "HIGH",
                        "Large declared archive expansion size",
                        f"ZIP metadata declares {total_uncompressed:,} uncompressed bytes; no data was extracted.",
                        18,
                    )
                )
                score += 18
            for info in infos:
                name = info.filename
                suffix = Path(name.replace("\\", "/")).suffix.lower()
                ratio = info.file_size / max(1, info.compress_size)
                normalized = name.replace("\\", "/")
                traversal = normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or ".." in normalized.split("/")
                markers: list[str] = []
                if suffix in DANGEROUS_ARCHIVE_SUFFIXES:
                    markers.append("executable/script-like content")
                elif suffix in ARCHIVE_SUFFIXES:
                    markers.append("nested archive (not opened)")
                if traversal:
                    markers.append("path-traversal-style member name")
                if info.flag_bits & 0x1:
                    markers.append("encrypted member")
                if ratio >= MAX_ARCHIVE_RATIO and info.file_size >= 1024 * 1024:
                    markers.append(f"high compression ratio ({ratio:.1f}:1)")
                    score += 12
                if markers:
                    report.archive_entries.append(f"{name} — {', '.join(markers)}")
                    if traversal:
                        score += 14
                    if suffix in DANGEROUS_ARCHIVE_SUFFIXES:
                        score += 5
                if len(report.archive_entries) >= 100:
                    report.archive_entries.append("... listing capped at 100 notable entries ...")
                    break
    except Exception as exc:  # malformed, adversarial archives must not crash analysis
        report.archive_error = f"ZIP metadata could not be parsed: {type(exc).__name__}: {exc}"
    return score


def analyze_binary(path: Path) -> BinaryReport:
    path = Path(path).expanduser().resolve()
    data, size_bytes, sampled, full_sha256 = read_target_details(path)
    file_type, details = identify(data)
    report = BinaryReport(
        path=path,
        data=data,
        size_bytes=size_bytes,
        sampled=sampled,
        file_type=file_type,
        details=details,
        sha256=full_sha256,
        entropy=entropy(data),
        strings=printable_strings(data),
    )
    if sampled:
        report.details += " | sampled analysis (first and last portions); SHA-256 covers the complete file"

    score = 0
    if report.entropy >= 7.2 and len(data) >= 4096:
        report.findings.append(
            Finding(
                "MEDIUM",
                "High file entropy",
                f"{report.entropy:.2f}/8.00 bits per byte; may indicate compression, encryption, or packing.",
                8,
            )
        )
        score += 8

    if data.startswith(b"MZ") and path.suffix.lower() not in EXECUTABLE_SUFFIXES:
        report.findings.append(
            Finding(
                "LOW",
                "Executable-like content / unusual extension",
                f"MZ signature found in a file named {path.name}; the PE signature is checked separately.",
                5,
            )
        )
        score += 5

    string_view = "\n".join(report.strings)
    for label, pattern, points in SUSPICIOUS_STRINGS:
        if pattern.search(string_view):
            report.findings.append(
                Finding("MEDIUM", label, "A static string indicator was found; inspect surrounding context.", points)
            )
            score += points

    if path.suffix.lower() in SCRIPT_SUFFIXES:
        report.findings.append(
            Finding(
                "INFO",
                "Script file",
                f"File extension {path.suffix.lower()} indicates a script; content was inspected as data only.",
                0,
            )
        )

    if file_type == "ZIP archive":
        if sampled:
            report.archive_error = "ZIP metadata inspection skipped: the file is larger than the full-read analysis limit."
        else:
            score += _inspect_zip(data, report)

    if data.startswith(b"MZ") and sampled:
        report.pe_error = "PE section/import analysis skipped in sampled mode to avoid incomplete parsing."
    elif data.startswith(b"MZ"):
        pe_offset = int.from_bytes(data[0x3C:0x40], "little") if len(data) >= 0x40 else -1
        valid_pe = 0x40 <= pe_offset <= len(data) - 4 and data[pe_offset:pe_offset + 4] == b"PE\x00\x00"
        if valid_pe:
            try:
                import pefile  # type: ignore

                pe = pefile.PE(data=data, fast_load=False)
                try:
                    for section in pe.sections:
                        name = section.Name.rstrip(b"\x00").decode("ascii", errors="replace") or "<unnamed>"
                        section_entropy = float(section.get_entropy())
                        chars = int(section.Characteristics)
                        executable = bool(chars & 0x20000000)
                        writable = bool(chars & 0x80000000)
                        readable = bool(chars & 0x40000000)
                        flags = "".join(("R" if readable else "-", "W" if writable else "-", "X" if executable else "-"))
                        report.pe_sections.append(
                            f"{name:<8} {flags}  entropy={section_entropy:.2f}  "
                            f"raw={int(section.SizeOfRawData):,}  virtual={int(section.Misc_VirtualSize):,}"
                        )
                        if executable and writable:
                            report.findings.append(
                                Finding("HIGH", f"RWX section: {name}", "Section is writable and executable; unusual in many ordinary binaries.", 20)
                            )
                            score += 20
                        if section_entropy >= 7.2 and int(section.SizeOfRawData) >= 2048:
                            report.findings.append(
                                Finding("MEDIUM", f"High-entropy PE section: {name}", f"Section entropy is {section_entropy:.2f}/8.00.", 8)
                            )
                            score += 8
                        if name.upper().startswith(("UPX", ".ASPACK", ".MPRESS")):
                            report.findings.append(
                                Finding("MEDIUM", f"Packer-like section name: {name}", "Section naming is associated with some packers but is not proof of malware.", 8)
                            )
                            score += 8

                    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                        seen: set[str] = set()
                        for entry in pe.DIRECTORY_ENTRY_IMPORT:
                            for imported in entry.imports:
                                if imported.name:
                                    api = imported.name.decode("ascii", errors="replace")
                                    if api not in seen:
                                        seen.add(api)
                                        report.imports.append(api)
                                    if api in SUSPICIOUS_APIS:
                                        description, points = SUSPICIOUS_APIS[api]
                                        report.findings.append(Finding("MEDIUM", f"Import: {api}", description, points))
                                        score += points
                    else:
                        report.findings.append(
                            Finding("INFO", "No ordinary import table", "Could be a minimal binary, packed file, or unusual PE.", 0)
                        )
                finally:
                    pe.close()
            except ImportError:
                report.pe_error = "pefile is not installed; PE section/import analysis is unavailable."
            except Exception as exc:  # malformed PE input must not crash the application
                report.pe_error = f"PE parser could not fully parse this file: {type(exc).__name__}: {exc}"
        else:
            report.pe_error = "MZ header found, but a valid PE signature was not found at the declared offset."

    # Deduplicate repeated indicators and cap the score. The score is not a probability.
    unique: dict[tuple[str, str], Finding] = {}
    for finding in report.findings:
        unique.setdefault((finding.title, finding.detail), finding)
    report.findings = list(unique.values())
    report.score = min(score, 100)
    if not report.findings:
        report.findings.append(
            Finding("INFO", "No configured indicators matched", "This does not prove the file is safe; static rules can miss threats.", 0)
        )
    return report


def query_osv(package_name: str, version: str, ecosystem: str) -> list[dict[str, Any]]:
    package_name, version, ecosystem = package_name.strip(), version.strip(), ecosystem.strip()
    if not package_name or not version or not ecosystem:
        raise ValueError("Package name, version, and ecosystem are all required")
    if len(package_name) > 200 or len(version) > 100 or len(ecosystem) > 80:
        raise ValueError("One or more fields are too long")
    payload = json.dumps(
        {"package": {"name": package_name, "ecosystem": ecosystem}, "version": version}
    ).encode("utf-8")
    req = urllib.request.Request(
        "https://api.osv.dev/v1/query",
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "User-Agent": f"MrDump/{VERSION}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("OSV response exceeded the 4 MiB safety limit")
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("OSV returned an unexpected response structure")
        vulnerabilities = result.get("vulns", []) or []
        if not isinstance(vulnerabilities, list):
            raise RuntimeError("OSV returned an unexpected response structure")
        return [item for item in vulnerabilities if isinstance(item, dict)]
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"OSV returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach OSV: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("OSV returned an invalid JSON response") from exc


def query_virustotal(file_hash: str, api_key: str | None = None) -> dict[str, Any]:
    api_key = (api_key or os.environ.get("VT_API_KEY", "")).strip()
    if not api_key:
        raise ValueError("VT_API_KEY is not set. Add your VirusTotal API key to the environment and restart MrDump.")
    if not re.fullmatch(r"[A-Fa-f0-9]{64}", file_hash):
        raise ValueError("A valid SHA-256 hash is required")
    req = urllib.request.Request(
        f"https://www.virustotal.com/api/v3/files/{file_hash.lower()}",
        headers={
            "x-apikey": api_key,
            "Accept": "application/json",
            "User-Agent": f"MrDump/{VERSION}",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
        if len(raw) > 4 * 1024 * 1024:
            raise RuntimeError("VirusTotal response exceeded the 4 MiB safety limit")
        result = json.loads(raw.decode("utf-8"))
        if not isinstance(result, dict):
            raise RuntimeError("VirusTotal returned an unexpected response structure")
        return result
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return {"not_found": True}
        if exc.code == 401:
            raise RuntimeError("VirusTotal rejected the API key (HTTP 401)") from exc
        if exc.code == 429:
            raise RuntimeError("VirusTotal rate limit reached (HTTP 429)") from exc
        raise RuntimeError(f"VirusTotal returned HTTP {exc.code}") from exc
    except (urllib.error.URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach VirusTotal: {exc}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise RuntimeError("VirusTotal returned an invalid JSON response") from exc


def run_clamav_scan(path: Path, timeout: int = 120) -> ScannerResult:
    """Run the optional local ClamAV CLI against one file; never uses a shell."""
    path = Path(path).expanduser()
    if not path.is_file():
        raise ValueError("Target file does not exist or is not a regular file")
    if timeout < 5 or timeout > 600:
        raise ValueError("ClamAV timeout must be between 5 and 600 seconds")
    executable = shutil.which("clamscan") or shutil.which("clamscan.exe")
    if not executable:
        return ScannerResult("ClamAV", "UNAVAILABLE", "clamscan was not found in PATH. Install ClamAV and update its signatures.")
    started = monotonic()
    try:
        completed = subprocess.run(
            [executable, "--no-summary", "--infected", str(path.resolve())],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
            shell=False,
        )
        duration = monotonic() - started
        output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
        if completed.returncode == 0:
            status = "CLEAN"
        elif completed.returncode == 1:
            status = "INFECTED"
        else:
            status = "ERROR"
        return ScannerResult("ClamAV", status, output or f"ClamAV exited with code {completed.returncode}.", completed.returncode, duration)
    except subprocess.TimeoutExpired as exc:
        duration = monotonic() - started
        output = "ClamAV scan timed out."
        if exc.stderr:
            output += f"\n{exc.stderr if isinstance(exc.stderr, str) else exc.stderr.decode(errors='replace')}"
        return ScannerResult("ClamAV", "ERROR", output, None, duration)
    except OSError as exc:
        return ScannerResult("ClamAV", "ERROR", f"Could not start ClamAV: {exc}", None, monotonic() - started)


def _is_allowed_address(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return any(ip in network for network in ALLOWED_NETWORKS)


def resolve_private_targets(target: str, max_hosts: int = MAX_NETWORK_HOSTS) -> list[str]:
    target = target.strip()
    if not target:
        raise ValueError("Enter a private IP address, private CIDR range, or hostname resolving only to private addresses")
    if max_hosts < 1 or max_hosts > MAX_NETWORK_HOSTS:
        raise ValueError(f"max_hosts must be between 1 and {MAX_NETWORK_HOSTS}")
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            if network.version != 4:
                raise ValueError("Only IPv4 networks are supported in this build")
            if network.num_addresses > max_hosts:
                raise ValueError(f"Network too large: maximum {max_hosts} addresses per scan")
            hosts = [str(ip) for ip in network.hosts()]
            if not hosts and network.num_addresses == 1:
                hosts = [str(network.network_address)]
        else:
            try:
                ip = ipaddress.ip_address(target)
                if ip.version != 4:
                    raise ValueError("Only IPv4 targets are supported in this build")
                hosts = [str(ip)]
            except ValueError as ip_error:
                if "Only IPv4" in str(ip_error):
                    raise
                records = socket.getaddrinfo(target, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
                hosts = sorted({record[4][0] for record in records})
                if not hosts:
                    raise ValueError("Hostname did not resolve to an IPv4 address")
    except ValueError:
        raise
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {exc}") from exc

    if len(hosts) > max_hosts:
        raise ValueError(f"Maximum {max_hosts} target addresses per scan")
    blocked = [ip for ip in hosts if not _is_allowed_address(ip)]
    if blocked:
        raise ValueError(
            "Public IPs are blocked. MrDump network scans are restricted to private, loopback, and link-local addresses."
        )
    return hosts


def parse_ports(value: str) -> list[int]:
    if not value.strip():
        raise ValueError("Enter at least one TCP port")
    parts = value.split(",")
    if any(not part.strip() for part in parts):
        raise ValueError("Empty port item detected; use comma-separated ports without extra commas")
    ports: set[int] = set()
    for raw_part in parts:
        part = raw_part.strip()
        if "-" in part:
            pieces = part.split("-")
            if len(pieces) != 2 or not all(piece.strip().isascii() and piece.strip().isdigit() for piece in pieces):
                raise ValueError(f"Invalid port range: {part}")
            start, end = (int(piece.strip()) for piece in pieces)
            if end < start or end - start >= 32:
                raise ValueError("Port ranges are limited to 32 consecutive ports")
            ports.update(range(start, end + 1))
        else:
            if not part.isascii() or not part.isdigit():
                raise ValueError(f"Invalid port: {part}")
            ports.add(int(part))
    if not ports:
        raise ValueError("Enter at least one TCP port")
    if len(ports) > MAX_NETWORK_PORTS:
        raise ValueError(f"Maximum {MAX_NETWORK_PORTS} TCP ports per scan")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def _check_tcp(host: str, port: int, timeout: float) -> tuple[str, int, bool]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return host, port, True
    except OSError:
        return host, port, False


def scan_private_network(
    target: str,
    ports_text: str,
    timeout: float = 0.65,
) -> tuple[list[str], list[tuple[str, int]]]:
    if not math.isfinite(timeout) or timeout < 0.1 or timeout > 5.0:
        raise ValueError("TCP timeout must be between 0.1 and 5 seconds")
    hosts = resolve_private_targets(target)
    ports = parse_ports(ports_text)
    jobs = [(host, port) for host in hosts for port in ports]
    if len(jobs) > MAX_NETWORK_JOBS:
        raise ValueError(
            f"Scan would exceed {MAX_NETWORK_JOBS} host/port checks; narrow the target range or port list"
        )
    open_ports: list[tuple[str, int]] = []
    with ThreadPoolExecutor(max_workers=min(96, max(1, len(jobs)))) as pool:
        futures = [pool.submit(_check_tcp, host, port, timeout) for host, port in jobs]
        for future in as_completed(futures):
            host, port, is_open = future.result()
            if is_open:
                open_ports.append((host, port))
    return hosts, sorted(open_ports)



def render_text_report(report: BinaryReport) -> str:
    """Build a readable plain-text report. No JSON export is provided."""
    lines = [
        f"MrDump {VERSION} — by aymen",
        "=" * 72,
        f"Target: {report.path}",
        f"Analyzed at (UTC): {report.analyzed_at}",
        f"File size: {report.size_bytes:,} bytes",
        f"File type: {report.file_type}",
        f"Format: {report.details}",
        f"SHA-256 (complete file): {report.sha256}",
        f"Entropy (analyzed bytes): {report.entropy:.4f}/8.0000",
        f"Analysis mode: {'SAMPLED' if report.sampled else 'FULL FILE'}",
        f"Heuristic score: {report.score}/100 (not a probability)",
        "",
        "MALWARE FINDINGS",
        "-" * 72,
    ]
    lines.extend(f"[{item.severity}] {item.title}: {item.detail}" for item in report.findings)
    lines.extend(["", "PE ANALYSIS", "-" * 72])
    lines.extend(report.pe_sections or ["No PE sections available."])
    lines.append(report.pe_error or "")
    lines.extend(["", "SELECTED IMPORTS", "-" * 72])
    lines.extend(report.imports or ["No imported APIs available."])
    lines.extend(["", "ZIP METADATA (NO EXTRACTION)", "-" * 72])
    lines.extend(report.archive_entries or ["No notable ZIP entries."])
    lines.append(report.archive_error or "")
    lines.extend(["", "EXTERNAL SCANS / LOOKUPS", "-" * 72])
    if report.external_scans:
        for scan in report.external_scans:
            lines.append(f"[{scan.get('engine', 'External')}] {scan.get('status', 'Result')}")
            detail = scan.get("output") or scan.get("detail") or ""
            if detail:
                lines.append(str(detail))
    else:
        lines.append("No external scans or lookups recorded.")
    lines.extend([
        "", "SAFETY NOTES", "-" * 72,
        "The inspected file was not executed or modified by MrDump.",
        "ZIP entries were inspected as metadata only; members were not extracted.",
        "Static indicators can produce false positives and false negatives.",
        "A clean result does not prove that a file is safe.",
        "For sampled files, entropy and strings describe the sampled regions only; SHA-256 covers the full file.",
        "",
    ])
    return "\n".join(lines)


def save_text_report(report: BinaryReport, destination: Path) -> Path:
    """Save a plain-text report without ever overwriting the inspected target or an existing file."""
    destination = Path(destination).expanduser()
    if not str(destination).strip():
        raise ValueError("Choose a destination for the text report")
    try:
        target_resolved = report.path.resolve()
        destination_resolved = destination.resolve(strict=False)
        if destination_resolved == target_resolved:
            raise ValueError("Security block: the report cannot overwrite the inspected file")
        if destination.exists() and destination.is_file() and report.path.exists():
            try:
                if os.path.samefile(destination, report.path):
                    raise ValueError("Security block: report destination is the inspected file")
            except OSError:
                pass
        destination.parent.mkdir(parents=True, exist_ok=True)
        # Exclusive creation prevents accidental overwrite of any existing file.
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        descriptor = os.open(str(destination), flags, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(render_text_report(report))
        except Exception:
            try:
                destination.unlink(missing_ok=True)
            except OSError:
                pass
            raise
        return destination
    except FileExistsError as exc:
        raise ValueError("That report file already exists. Choose another name; existing files are never overwritten.") from exc
    except OSError as exc:
        raise ValueError(f"Could not write text report: {exc}") from exc

