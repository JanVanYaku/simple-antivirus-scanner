#######################################################################
# Author: Lehlohonolo Adolf Matobakele
# Email: lehlohonolo.matobakele@gov.ls
# Contacxt: 00266 62320704
#######################################################################

"""Simple antivirus-style scanner using local signature engines."""

from __future__ import annotations

import argparse
import csv
import glob
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table


console = Console()


EICAR_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}"
    b"$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)
DEFAULT_QUARANTINE_DIR = Path.home() / ".simple_antivirus_quarantine"
DEFAULT_MAX_SIZE_MB = 256
SUPPORTED_ENGINES = {"local", "clamav", "defender", "avast", "kaspersky"}


@dataclass
class EngineStatus:
    """Availability information for one scan engine."""

    engine: str
    available: bool
    version: str
    detail: str


@dataclass
class Signature:
    """One custom hash signature."""

    sha256: str
    name: str
    malware_type: str
    severity: str


@dataclass
class Detection:
    """One antivirus finding."""

    path: str
    engine: str
    threat_name: str
    malware_type: str
    severity: str
    evidence: str
    sha256: str
    action: str = "pending"
    action_detail: str = ""


@dataclass
class ScanReport:
    """Serializable scan report."""

    generated_at: str
    target: str
    engines: list[str]
    files_scanned: int
    detections: list[Detection]
    explanation: str


def run_command(command: list[str], timeout: int = 300) -> tuple[int, str]:
    """Run a command and return exit code plus combined output."""

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 1, str(exc)
    return completed.returncode, completed.stdout + completed.stderr


def find_existing_executable(candidates: list[str | Path]) -> str:
    """Return the first executable found in PATH or common install locations."""

    for candidate in candidates:
        text = str(candidate)
        found = shutil.which(text)
        if found:
            return found
        matches = glob.glob(text) if any(char in text for char in "*?") else []
        for match in matches:
            path_match = Path(match)
            if path_match.is_file():
                return str(path_match)
        path = Path(text)
        if path.is_file():
            return str(path)
    return ""


def env_or_find(env_name: str, candidates: list[str | Path]) -> str:
    """Use an environment variable path first, otherwise search candidates."""

    override = os.environ.get(env_name, "").strip()
    if override and Path(override).is_file():
        return override
    return find_existing_executable(candidates)


def sibling_executable(path_text: str, executable: str) -> str:
    """Find an executable next to another discovered executable."""

    if not path_text:
        return ""
    candidate = Path(path_text).with_name(executable)
    return str(candidate) if candidate.is_file() else ""


def env_override_note(env_names: list[str]) -> str:
    """Describe configured environment overrides and whether they exist."""

    notes: list[str] = []
    for name in env_names:
        value = os.environ.get(name, "").strip()
        if not value:
            continue
        state = "exists" if Path(value).is_file() else "not found"
        notes.append(f"{name}={value} ({state})")
    return "; ".join(notes)


def friendly_engine_output(output: str) -> str:
    """Add practical guidance to common external engine errors."""

    text = output.strip()
    lowered = text.lower()
    if "winerror 216" in lowered or "not compatible with the version of windows" in lowered:
        return (
            f"{text}\n\n"
            "The executable was found, but Windows cannot run it on this architecture. "
            "Install the ClamAV build that matches your Windows architecture, or set "
            "CLAMAV_CLAMSCAN_PATH/CLAMAV_FRESHCLAM_PATH to compatible executables."
        )
    if "winerror 740" in lowered or "requires elevation" in lowered:
        return f"{text}\n\nOpen PowerShell as Administrator and run the command again."
    return text


def program_files_candidates(*parts: str, executable: str) -> list[Path]:
    """Build Program Files candidate paths for Windows tools."""

    candidates: list[Path] = []
    for env_name in ["ProgramFiles", "ProgramFiles(x86)"]:
        root = os.environ.get(env_name)
        if root:
            candidates.append(Path(root).joinpath(*parts, executable))
    return candidates


def sha256_file(path: Path) -> str:
    """Calculate a file SHA-256 hash."""

    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_contains_bytes(path: Path, needle: bytes) -> bool:
    """Search for a byte signature without loading huge files into memory."""

    overlap = max(len(needle) - 1, 0)
    previous = b""
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            haystack = previous + chunk
            if needle in haystack:
                return True
            previous = haystack[-overlap:] if overlap else b""
    return False


def iter_files(target: Path, max_size_mb: int) -> tuple[list[Path], list[str]]:
    """Collect readable files under a target path."""

    max_size = max_size_mb * 1024 * 1024
    skipped: list[str] = []
    files: list[Path] = []

    if target.is_file():
        candidates: Iterable[Path] = [target]
    elif target.is_dir():
        candidates = (path for path in target.rglob("*") if path.is_file())
    else:
        return [], [f"Target does not exist: {target}"]

    for path in candidates:
        try:
            size = path.stat().st_size
        except OSError as exc:
            skipped.append(f"{path}: {exc}")
            continue
        if size > max_size:
            skipped.append(f"{path}: skipped because it is larger than {max_size_mb} MB")
            continue
        files.append(path)
    return files, skipped


def load_signature_db(path: Path | None) -> list[Signature]:
    """Load optional custom SHA-256 signatures."""

    signatures = [
        Signature(
            sha256=hashlib.sha256(EICAR_BYTES).hexdigest(),
            name="EICAR-Test-File",
            malware_type="test-file",
            severity="TEST",
        )
    ]
    if not path:
        return signatures

    data = json.loads(path.read_text(encoding="utf-8"))
    records = data.get("signatures", data) if isinstance(data, dict) else data
    for record in records:
        signatures.append(
            Signature(
                sha256=str(record["sha256"]).lower(),
                name=str(record.get("name", "Custom.Signature")),
                malware_type=str(record.get("type", record.get("malware_type", "unknown"))),
                severity=str(record.get("severity", "HIGH")).upper(),
            )
        )
    return signatures


def scan_with_local_signatures(
    target: Path,
    signature_db: Path | None,
    max_size_mb: int,
) -> tuple[list[Detection], int, list[str]]:
    """Scan files with local hash signatures and the harmless EICAR test pattern."""

    signatures = {signature.sha256.lower(): signature for signature in load_signature_db(signature_db)}
    files, skipped = iter_files(target, max_size_mb=max_size_mb)
    detections: list[Detection] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Local signature scan", total=len(files))
        for path in files:
            try:
                digest = sha256_file(path)
                if digest in signatures:
                    signature = signatures[digest]
                    detections.append(
                        Detection(
                            path=str(path.resolve()),
                            engine="local-signatures",
                            threat_name=signature.name,
                            malware_type=signature.malware_type,
                            severity=signature.severity,
                            evidence=f"SHA-256 matched {signature.name}",
                            sha256=digest,
                        )
                    )
                elif file_contains_bytes(path, EICAR_BYTES):
                    detections.append(
                        Detection(
                            path=str(path.resolve()),
                            engine="local-signatures",
                            threat_name="EICAR-Test-File",
                            malware_type="test-file",
                            severity="TEST",
                            evidence="File contains the harmless EICAR antivirus test string.",
                            sha256=digest,
                        )
                    )
            except OSError as exc:
                skipped.append(f"{path}: {exc}")
            finally:
                progress.advance(task)

    return detections, len(files), skipped


def clamav_paths() -> tuple[str, str]:
    """Return ClamAV scanner and updater paths when installed."""

    scanner = env_or_find(
        "CLAMAV_CLAMSCAN_PATH",
        [
            "clamscan.exe",
            "clamscan",
            *program_files_candidates("ClamAV", executable="clamscan.exe"),
            Path("C:/ProgramData/chocolatey/bin/clamscan.exe"),
        ],
    )
    updater_candidates: list[str | Path] = [
        "freshclam.exe",
        "freshclam",
        *program_files_candidates("ClamAV", executable="freshclam.exe"),
        Path("C:/ProgramData/chocolatey/bin/freshclam.exe"),
    ]
    sibling_updater = sibling_executable(scanner, "freshclam.exe")
    if sibling_updater:
        updater_candidates.insert(0, sibling_updater)
    updater = env_or_find("CLAMAV_FRESHCLAM_PATH", updater_candidates)
    if updater and not scanner:
        scanner = sibling_executable(updater, "clamscan.exe")
    return scanner, updater


def clamav_status() -> EngineStatus:
    """Check ClamAV availability."""

    clamscan, freshclam = clamav_paths()
    if not clamscan:
        override_note = env_override_note(["CLAMAV_CLAMSCAN_PATH", "CLAMAV_FRESHCLAM_PATH"])
        detail = "Install ClamAV and run freshclam to use its known malware signature database."
        if override_note:
            detail += f" Overrides: {override_note}."
        return EngineStatus(
            engine="clamav",
            available=False,
            version="not installed",
            detail=detail,
        )
    code, output = run_command([clamscan, "--version"], timeout=30)
    friendly_output = friendly_engine_output(output)
    version = output.strip().splitlines()[0] if output.strip() else "available"
    if code != 0 and ("winerror 216" in output.lower() or "not compatible with the version of windows" in output.lower()):
        version = "incompatible executable"
    detail = f"scanner={clamscan}"
    if freshclam:
        detail += f"; updater={freshclam}"
    if code != 0 and friendly_output:
        detail += f"; error={friendly_output}"
    return EngineStatus("clamav", code == 0, version, detail)


def defender_status() -> EngineStatus:
    """Check Windows Defender availability."""

    if platform.system().lower() != "windows":
        return EngineStatus("defender", False, "not windows", "Windows Defender is only available on Windows.")

    command = [
        "powershell",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-Command",
        (
            "$status = Get-MpComputerStatus; "
            "[pscustomobject]@{"
            "AntivirusEnabled=$status.AntivirusEnabled;"
            "RealTimeProtectionEnabled=$status.RealTimeProtectionEnabled;"
            "SignatureAge=$status.AntivirusSignatureAge;"
            "SignatureVersion=$status.AntivirusSignatureVersion"
            "} | ConvertTo-Json -Compress"
        ),
    ]
    code, output = run_command(command, timeout=60)
    if code != 0:
        return EngineStatus("defender", False, "unavailable", output.strip()[:300])
    return EngineStatus("defender", True, "Microsoft Defender", output.strip())


def avast_paths() -> tuple[str, str]:
    """Return Avast scanner and updater paths when installed."""

    scanner_candidates = [
        "ashCmd.exe",
        *program_files_candidates("AVAST Software", "Avast", executable="ashCmd.exe"),
        *program_files_candidates("AVAST Software", "Suite", executable="ashCmd.exe"),
        *program_files_candidates("Avast Software", "Avast", executable="ashCmd.exe"),
        *program_files_candidates("Avast Software", "Suite", executable="ashCmd.exe"),
    ]
    scanner = env_or_find("AVAST_ASHCMD_PATH", scanner_candidates)

    updater_candidates: list[str | Path] = [
        "ashUpd.exe",
        *program_files_candidates("AVAST Software", "Avast", executable="ashUpd.exe"),
        *program_files_candidates("AVAST Software", "Suite", executable="ashUpd.exe"),
        *program_files_candidates("Avast Software", "Avast", executable="ashUpd.exe"),
        *program_files_candidates("Avast Software", "Suite", executable="ashUpd.exe"),
    ]
    sibling_updater = sibling_executable(scanner, "ashUpd.exe")
    if sibling_updater:
        updater_candidates.insert(0, sibling_updater)
    updater = env_or_find("AVAST_ASHUPD_PATH", updater_candidates)

    if updater and not scanner:
        scanner = sibling_executable(updater, "ashCmd.exe")
    return scanner, updater


def avast_status() -> EngineStatus:
    """Check Avast command-line scanner availability."""

    scanner, updater = avast_paths()
    if not scanner:
        override_note = env_override_note(["AVAST_ASHCMD_PATH", "AVAST_ASHUPD_PATH"])
        detail = (
            "Avast ashCmd.exe was not found, so Avast command-line scanning is unavailable. "
            "Avast One may include ashUpd.exe for updates without including ashCmd.exe for scans. "
            "Install an Avast edition that provides ashCmd.exe or set AVAST_ASHCMD_PATH."
        )
        if updater:
            detail += f" Updater found: {updater}."
        if override_note:
            detail += f" Overrides: {override_note}."
        return EngineStatus(
            engine="avast",
            available=False,
            version="not installed",
            detail=detail,
        )
    detail = f"scanner={scanner}"
    if updater:
        detail += f"; updater={updater}"
    code, output = run_command([scanner, "/?"], timeout=30)
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    version = first_line[:120] if first_line else "Avast command-line scanner"
    return EngineStatus("avast", code in {0, 1}, version, detail)


def kaspersky_paths() -> tuple[str, str]:
    """Return Kaspersky avp.com and kescli.exe paths when installed."""

    avp = env_or_find(
        "KASPERSKY_AVP_PATH",
        [
            "avp.com",
            *program_files_candidates("Kaspersky Lab", "*", executable="avp.com"),
            *program_files_candidates("Kaspersky", "*", executable="avp.com"),
        ],
    )
    kescli = env_or_find(
        "KASPERSKY_KESCLI_PATH",
        [
            "kescli.exe",
            "kescli",
            *program_files_candidates("Kaspersky Lab", "*", executable="kescli.exe"),
            *program_files_candidates("Kaspersky", "*", executable="kescli.exe"),
        ],
    )
    return avp, kescli


def kaspersky_status() -> EngineStatus:
    """Check Kaspersky command-line scanner availability."""

    avp, kescli = kaspersky_paths()
    if not avp and not kescli:
        return EngineStatus(
            engine="kaspersky",
            available=False,
            version="not installed",
            detail=(
                "Kaspersky avp.com/kescli.exe was not found. Install Kaspersky "
                "or set KASPERSKY_AVP_PATH/KASPERSKY_KESCLI_PATH."
            ),
        )

    if avp:
        code, output = run_command([avp, "VERSION"], timeout=30)
        first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
        version = first_line[:120] if first_line else "Kaspersky avp.com"
        detail = f"avp={avp}"
        if kescli:
            detail += f"; kescli={kescli}"
        return EngineStatus("kaspersky", code == 0, version, detail)

    code, output = run_command([kescli, "--opswat", "GetDefinitionState"], timeout=30)
    first_line = next((line.strip() for line in output.splitlines() if line.strip()), "")
    version = first_line[:120] if first_line else "Kaspersky kescli"
    return EngineStatus("kaspersky", code == 0, version, f"kescli={kescli}")


def render_engine_status(statuses: list[EngineStatus]) -> None:
    """Print engine status table."""

    table = Table(title="Antivirus Engine Status", show_lines=True)
    table.add_column("Engine")
    table.add_column("Available")
    table.add_column("Version")
    table.add_column("Detail", overflow="fold")
    for status in statuses:
        table.add_row(
            status.engine,
            "yes" if status.available else "no",
            status.version,
            status.detail or "-",
        )
    console.print(table)


def scan_with_clamav(target: Path, timeout: int) -> tuple[list[Detection], int, list[str]]:
    """Run ClamAV clamscan and parse detections."""

    clamscan, _ = clamav_paths()
    if not clamscan:
        return [], 0, ["ClamAV clamscan was not found."]

    command = [clamscan, "--recursive=yes", "--infected", "--no-summary", str(target)]
    code, output = run_command(command, timeout=timeout)
    detections: list[Detection] = []
    notes: list[str] = []

    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.endswith("FOUND") and ": " in line:
            file_text, threat_text = line.rsplit(": ", 1)
            threat_name = threat_text.removesuffix(" FOUND").strip()
            file_path = Path(file_text)
            digest = ""
            try:
                digest = sha256_file(file_path)
            except OSError:
                pass
            detections.append(
                Detection(
                    path=str(file_path.resolve()),
                    engine="clamav",
                    threat_name=threat_name,
                    malware_type=classify_threat(threat_name),
                    severity="HIGH",
                    evidence=f"ClamAV signature matched {threat_name}",
                    sha256=digest,
                )
            )
        elif "ERROR" in line.upper():
            notes.append(line)

    if code not in {0, 1} and output:
        notes.append(friendly_engine_output(output)[:1500])
    return detections, 0, notes


def scan_with_defender(target: Path, timeout: int) -> tuple[list[Detection], int, list[str]]:
    """Run a Windows Defender custom scan and query matching detections."""

    status = defender_status()
    if not status.available:
        return [], 0, [status.detail]

    target_text = str(target.resolve())
    script = f"""
$ErrorActionPreference = 'Stop'
$scanPath = {json.dumps(target_text)}
Start-MpScan -ScanType CustomScan -ScanPath $scanPath
$detections = Get-MpThreatDetection | Where-Object {{
    ($_.Resources -join '|') -like "*$scanPath*"
}} | Select-Object ThreatName, ThreatID, SeverityID, Resources, InitialDetectionTime, ActionSuccess
$detections | ConvertTo-Json -Depth 5 -Compress
"""
    command = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]
    code, output = run_command(command, timeout=timeout)
    if code != 0:
        return [], 0, [output.strip()[:1000]]
    if not output.strip():
        return [], 0, []

    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return [], 0, [output.strip()[:1000]]

    records = data if isinstance(data, list) else [data]
    detections: list[Detection] = []
    for record in records:
        resources = record.get("Resources") or []
        if isinstance(resources, str):
            resources = [resources]
        resource_path = next((item for item in resources if str(item)), target_text)
        detections.append(
            Detection(
                path=str(Path(resource_path).resolve()),
                engine="defender",
                threat_name=str(record.get("ThreatName", "Microsoft Defender Detection")),
                malware_type=classify_threat(str(record.get("ThreatName", ""))),
                severity=defender_severity(record.get("SeverityID")),
                evidence=f"Microsoft Defender threat id {record.get('ThreatID', 'unknown')}",
                sha256="",
                action="handled-by-defender" if record.get("ActionSuccess") else "pending",
                action_detail="Microsoft Defender may have already quarantined or remediated this item.",
            )
        )
    return detections, 0, []


def parse_vendor_detections(
    engine: str,
    target: Path,
    output: str,
    report_text: str = "",
) -> list[Detection]:
    """Parse common vendor scanner output into Detection objects."""

    combined = "\n".join(part for part in [output, report_text] if part)
    detections: list[Detection] = []
    seen: set[tuple[str, str]] = set()
    keywords = ["eicar", "infected", "infection", "malware", "trojan", "worm", "virus", "threat", "found"]
    clean_phrases = ["no threat", "no threats", "no virus", "no viruses", "0 infected", "nothing found"]

    for raw_line in combined.splitlines():
        line = raw_line.strip()
        lowered = line.lower()
        if not line:
            continue
        if any(phrase in lowered for phrase in clean_phrases):
            continue
        if not any(keyword in lowered for keyword in keywords):
            continue

        file_path = extract_detection_path(line, target)
        threat_name = extract_threat_name(line, engine)
        key = (str(file_path).lower(), threat_name.lower())
        if key in seen:
            continue
        seen.add(key)
        digest = ""
        try:
            if file_path.exists() and file_path.is_file():
                digest = sha256_file(file_path)
        except OSError:
            pass
        detections.append(
            Detection(
                path=str(file_path.resolve()) if file_path.exists() else str(file_path),
                engine=engine,
                threat_name=threat_name,
                malware_type=classify_threat(threat_name),
                severity="HIGH",
                evidence=line[:500],
                sha256=digest,
            )
        )
    return detections


def extract_detection_path(line: str, target: Path) -> Path:
    """Extract a likely file path from scanner output."""

    quoted = re_find_quoted_path(line)
    if quoted:
        return Path(quoted)

    for marker in [" : ", ": ", "\t"]:
        if marker in line:
            candidate = line.rsplit(marker, 1)[0].strip()
            if len(candidate) > 2:
                path = Path(candidate.strip('"'))
                if path.exists() or "\\" in candidate or "/" in candidate:
                    return path
    return target


def re_find_quoted_path(line: str) -> str:
    """Find a quoted Windows or POSIX path in a line of scanner output."""

    import re

    match = re.search(r'"([A-Za-z]:\\[^"]+|/[^"]+)"', line)
    return match.group(1) if match else ""


def extract_threat_name(line: str, engine: str) -> str:
    """Extract a likely threat name from scanner output."""

    import re

    patterns = [
        r"FOUND\s*:?\s*(.+)$",
        r"Threat(?:Name)?\s*[:=]\s*(.+)$",
        r"Virus\s*[:=]\s*(.+)$",
        r"Infected\s*[:=]\s*(.+)$",
        r"Malware\s*[:=]\s*(.+)$",
    ]
    for pattern in patterns:
        match = re.search(pattern, line, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip().strip('"')[:120]
    if ":" in line:
        tail = line.rsplit(":", 1)[-1].strip()
        if tail:
            return tail[:120]
    return f"{engine.title()} Detection"


def scan_with_avast(target: Path, timeout: int) -> tuple[list[Detection], int, list[str]]:
    """Run Avast ashCmd.exe and parse possible detections."""

    scanner, _ = avast_paths()
    if not scanner:
        return [], 0, ["Avast ashCmd.exe was not found."]

    report_path = Path(tempfile.gettempdir()) / f"simple_avast_scan_{int(time.time())}.txt"
    command = [
        scanner,
        str(target),
        "/_",
        "/a",
        "/c",
        "/d",
        "/s",
        "/p=4",
        f"/r={report_path}",
    ]
    code, output = run_command(command, timeout=timeout)
    report_text = ""
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8", errors="replace")
    detections = parse_vendor_detections("avast", target, output, report_text)
    notes: list[str] = []
    if code == 1 and not detections:
        detections.append(
            Detection(
                path=str(target.resolve()),
                engine="avast",
                threat_name="Avast Threat Detected",
                malware_type="malware",
                severity="HIGH",
                evidence="Avast returned exit code 1, which indicates a detected threat.",
                sha256="",
            )
        )
    elif code not in {0, 1}:
        notes.append(friendly_engine_output(output or report_text or f"Avast exited with code {code}")[:1500])
    return detections, 0, notes


def scan_with_kaspersky(target: Path, timeout: int) -> tuple[list[Detection], int, list[str]]:
    """Run Kaspersky avp.com or kescli.exe and parse possible detections."""

    avp, kescli = kaspersky_paths()
    if not avp and not kescli:
        return [], 0, ["Kaspersky avp.com/kescli.exe was not found."]

    report_path = Path(tempfile.gettempdir()) / f"simple_kaspersky_scan_{int(time.time())}.txt"
    if avp:
        command = [avp, "SCAN", str(target), "/i0", f"/R:{report_path}"]
        engine_name = "kaspersky"
    else:
        command = [kescli, "--opswat", "Scan", str(target), "0"]
        engine_name = "kaspersky"

    code, output = run_command(command, timeout=timeout)
    report_text = ""
    if report_path.exists():
        report_text = report_path.read_text(encoding="utf-8", errors="replace")
    detections = parse_vendor_detections(engine_name, target, output, report_text)
    notes: list[str] = []
    if code not in {0, 1} and output:
        notes.append(friendly_engine_output(output)[:1500])
    return detections, 0, notes


def defender_severity(value: object) -> str:
    """Convert Defender severity ID to a readable severity."""

    try:
        number = int(value)
    except (TypeError, ValueError):
        return "UNKNOWN"
    if number >= 5:
        return "HIGH"
    if number >= 3:
        return "MEDIUM"
    return "LOW"


def classify_threat(name: str) -> str:
    """Make a simple malware type guess from a signature name."""

    lowered = name.lower()
    for keyword in ["worm", "trojan", "ransom", "spyware", "adware", "rootkit", "backdoor"]:
        if keyword in lowered:
            return keyword
    if "eicar" in lowered:
        return "test-file"
    if "virus" in lowered:
        return "virus"
    return "malware"


def resolve_engines(requested: str) -> list[str]:
    """Resolve engine selection to a list of engines."""

    value = requested.lower()
    if value == "auto":
        engines = ["local"]
        if clamav_status().available:
            engines.append("clamav")
        if avast_status().available:
            engines.append("avast")
        if kaspersky_status().available:
            engines.append("kaspersky")
        if defender_status().available:
            engines.append("defender")
        return engines
    if value == "all":
        return ["local", "clamav", "avast", "kaspersky", "defender"]
    engines = [item.strip() for item in value.split(",") if item.strip()]
    invalid = [engine for engine in engines if engine not in SUPPORTED_ENGINES]
    if invalid:
        raise argparse.ArgumentTypeError(f"Unsupported engine(s): {', '.join(invalid)}")
    return engines


def dedupe_detections(detections: list[Detection]) -> list[Detection]:
    """Remove duplicate engine/path/threat detections."""

    seen: set[tuple[str, str, str]] = set()
    unique: list[Detection] = []
    for detection in detections:
        key = (detection.path.lower(), detection.engine, detection.threat_name.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(detection)
    return unique


def render_detections(detections: list[Detection]) -> None:
    """Print detection table."""

    table = Table(title="Antivirus Scan Results", show_lines=True)
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Engine", overflow="fold")
    table.add_column("Severity")
    table.add_column("Threat", overflow="fold")
    table.add_column("Type")
    table.add_column("File", overflow="fold")
    table.add_column("Evidence", overflow="fold")

    if not detections:
        table.add_row("-", "-", "CLEAN", "-", "-", "No detections found.", "-")
    for index, detection in enumerate(detections, start=1):
        color = "red" if detection.severity in {"HIGH", "CRITICAL"} else "yellow"
        if detection.severity in {"LOW", "TEST"}:
            color = "green"
        table.add_row(
            str(index),
            detection.engine,
            f"[{color}]{detection.severity}[/{color}]",
            detection.threat_name,
            detection.malware_type,
            detection.path,
            detection.evidence,
        )
    console.print(table)


def explain_results(
    detections: list[Detection],
    engines: list[str],
    files_scanned: int,
    notes: list[str] | None = None,
) -> str:
    """Explain scan results in plain language."""

    engine_text = ", ".join(engines)
    if not detections:
        if notes:
            return (
                f"No detections were reported by {engine_text}, but at least one engine produced a warning "
                "or error. Check the Scan Notes section before treating this as a clean result."
            )
        if files_scanned <= 0:
            return (
                f"The scan completed with {engine_text}, and no detections were reported. "
                "Some external engines do not return a file count to this wrapper. If an engine was not installed "
                "or could not run, check the Scan Notes section."
            )
        return (
            f"Scanned {files_scanned} file(s) with {engine_text}. No detections were found. "
            "This is good, but it does not prove the machine is completely clean. Keep signatures updated, "
            "scan suspicious downloads, and use a trusted real-time antivirus."
        )

    counts = Counter(detection.malware_type for detection in detections)
    type_text = ", ".join(f"{name} ({count})" for name, count in counts.most_common())
    return (
        f"Found {len(detections)} detection(s) while scanning with {engine_text}. "
        f"Detected categories: {type_text}. Quarantine is usually the safest first action because it "
        "isolates the file while preserving it for review. Delete only when you are confident the file is unwanted."
    )


def quarantine_file(path: Path, quarantine_dir: Path, detection: Detection) -> tuple[str, str]:
    """Move a detected file into quarantine and write metadata."""

    if not path.exists():
        return "missing", "File was not found; it may already have been removed."

    quarantine_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    digest = detection.sha256 or sha256_file(path)
    safe_name = path.name.replace(os.sep, "_")
    destination = quarantine_dir / f"{timestamp}_{digest[:12]}_{safe_name}"
    shutil.move(str(path), str(destination))
    metadata = {
        "original_path": str(path.resolve()),
        "quarantine_path": str(destination.resolve()),
        "detection": asdict(detection),
        "quarantined_at": datetime.now(timezone.utc).isoformat(),
    }
    destination.with_suffix(destination.suffix + ".metadata.json").write_text(
        json.dumps(metadata, indent=2),
        encoding="utf-8",
    )
    return "quarantined", str(destination.resolve())


def delete_file(path: Path) -> tuple[str, str]:
    """Delete a detected file."""

    if not path.exists():
        return "missing", "File was not found; it may already have been removed."
    path.unlink()
    return "deleted", "File deleted."


def apply_actions(
    detections: list[Detection],
    action: str,
    quarantine_dir: Path,
) -> list[Detection]:
    """Ask for or apply actions against detected files."""

    if not detections:
        return detections

    unique_paths: dict[str, list[Detection]] = {}
    for detection in detections:
        unique_paths.setdefault(detection.path, []).append(detection)

    for path_text, related in unique_paths.items():
        file_path = Path(path_text)
        selected = action
        if selected == "ask":
            console.print(f"\n[bold]Detection:[/bold] {path_text}")
            for detection in related:
                console.print(f"- {detection.engine}: {detection.threat_name} ({detection.severity})")
            selected = prompt_action()

        if selected == "ignore":
            result, detail = "ignored", "User chose to ignore this detection."
        elif selected == "quarantine":
            result, detail = quarantine_file(file_path, quarantine_dir, related[0])
        elif selected == "delete":
            result, detail = delete_file(file_path)
        else:
            result, detail = "ignored", "Unknown action; defaulted to ignore."

        for detection in related:
            detection.action = result
            detection.action_detail = detail
    return detections


def prompt_action() -> str:
    """Prompt user for a detection action."""

    while True:
        choice = input("Choose action: [q]uarantine, [d]elete, [i]gnore: ").strip().lower()
        if choice in {"q", "quarantine"}:
            return "quarantine"
        if choice in {"d", "delete"}:
            confirm = input("Type DELETE to permanently delete this file: ").strip()
            return "delete" if confirm == "DELETE" else "ignore"
        if choice in {"i", "ignore", ""}:
            return "ignore"
        console.print("[yellow]Please choose q, d, or i.[/yellow]")


def write_json_report(path: Path, report: ScanReport) -> None:
    """Write JSON report."""

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(report), indent=2), encoding="utf-8")


def write_csv_report(path: Path, detections: list[Detection]) -> None:
    """Write detection summary as CSV."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(asdict(detections[0]).keys()) if detections else ["path"])
        writer.writeheader()
        for detection in detections:
            writer.writerow(asdict(detection))


def run_status(args: argparse.Namespace) -> int:
    """Show engine status."""

    del args
    render_engine_status(
        [
            clamav_status(),
            avast_status(),
            kaspersky_status(),
            defender_status(),
            EngineStatus("local", True, "built-in", "EICAR test and optional SHA-256 signature DB."),
        ]
    )
    return 0


def run_update(args: argparse.Namespace) -> int:
    """Update local engine signatures where supported."""

    engines = resolve_engines(args.engine)
    for engine in engines:
        if engine == "clamav":
            _, freshclam = clamav_paths()
            if not freshclam:
                override_note = env_override_note(["CLAMAV_CLAMSCAN_PATH", "CLAMAV_FRESHCLAM_PATH"])
                message = "freshclam was not found. Install ClamAV or set CLAMAV_FRESHCLAM_PATH."
                if override_note:
                    message += f" Overrides: {override_note}."
                console.print(f"[yellow]{message}[/yellow]")
                continue
            code, output = run_command([freshclam], timeout=args.timeout)
            console.print(
                Panel(friendly_engine_output(output) or f"freshclam exited with code {code}", title="ClamAV Update")
            )
        elif engine == "defender":
            if platform.system().lower() != "windows":
                console.print("[yellow]Windows Defender updates are only available on Windows.[/yellow]")
                continue
            code, output = run_command(
                ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "Update-MpSignature"],
                timeout=args.timeout,
            )
            console.print(
                Panel(
                    friendly_engine_output(output) or f"Update-MpSignature exited with code {code}",
                    title="Defender Update",
                )
            )
        elif engine == "avast":
            scanner, updater = avast_paths()
            if not updater:
                message = "Avast ashUpd.exe was not found. Install Avast or set AVAST_ASHUPD_PATH."
                if scanner:
                    expected = Path(scanner).with_name("ashUpd.exe")
                    message += f" Found ashCmd.exe at {scanner}; expected updater at {expected}."
                override_note = env_override_note(["AVAST_ASHCMD_PATH", "AVAST_ASHUPD_PATH"])
                if override_note:
                    message += f" Overrides: {override_note}."
                console.print(f"[yellow]{message}[/yellow]")
                continue
            code, output = run_command([updater, "vps"], timeout=args.timeout)
            console.print(
                Panel(friendly_engine_output(output) or f"ashUpd.exe exited with code {code}", title="Avast VPS Update")
            )
        elif engine == "kaspersky":
            avp, kescli = kaspersky_paths()
            if avp:
                code, output = run_command([avp, "UPDATE"], timeout=args.timeout)
                console.print(
                    Panel(
                        friendly_engine_output(output) or f"avp.com UPDATE exited with code {code}",
                        title="Kaspersky Update",
                    )
                )
            elif kescli:
                code, output = run_command([kescli, "--opswat", "UpdateDefinitions"], timeout=args.timeout)
                console.print(
                    Panel(
                        friendly_engine_output(output) or f"kescli UpdateDefinitions exited with code {code}",
                        title="Kaspersky Update",
                    )
                )
            else:
                console.print("[yellow]Kaspersky avp.com/kescli.exe was not found.[/yellow]")
        elif engine == "local":
            console.print("[blue]Local signatures do not need updates unless you provide a new --signature-db file.[/blue]")
    return 0


def run_scan(args: argparse.Namespace) -> int:
    """Run antivirus scan."""

    target = args.target.resolve()
    engines = resolve_engines(args.engine)
    console.print(
        Panel(
            f"Target: [bold]{target}[/bold]\n"
            f"Engines: [bold]{', '.join(engines)}[/bold]\n"
            f"Action after scan: [bold]{args.action}[/bold]\n"
            f"Quarantine directory: [bold]{args.quarantine_dir.resolve()}[/bold]",
            title="Simple Antivirus Scan",
            border_style="cyan",
        )
    )

    all_detections: list[Detection] = []
    notes: list[str] = []
    files_scanned = 0
    for engine in engines:
        if engine == "local":
            detections, count, engine_notes = scan_with_local_signatures(
                target,
                args.signature_db,
                max_size_mb=args.max_size_mb,
            )
            files_scanned = max(files_scanned, count)
        elif engine == "clamav":
            detections, count, engine_notes = scan_with_clamav(target, timeout=args.timeout)
            files_scanned = max(files_scanned, count)
        elif engine == "defender":
            detections, count, engine_notes = scan_with_defender(target, timeout=args.timeout)
            files_scanned = max(files_scanned, count)
        elif engine == "avast":
            detections, count, engine_notes = scan_with_avast(target, timeout=args.timeout)
            files_scanned = max(files_scanned, count)
        elif engine == "kaspersky":
            detections, count, engine_notes = scan_with_kaspersky(target, timeout=args.timeout)
            files_scanned = max(files_scanned, count)
        else:
            detections, count, engine_notes = [], 0, [f"Unknown engine: {engine}"]
        all_detections.extend(detections)
        notes.extend(engine_notes)

    detections = dedupe_detections(all_detections)
    render_detections(detections)
    explanation = explain_results(detections, engines, files_scanned, notes)
    console.print(Panel(explanation, title="Result Explanation", border_style="blue"))

    if notes:
        note_panel = "\n".join(notes[:12])
        console.print(Panel(note_panel, title="Scan Notes", border_style="yellow"))

    detections = apply_actions(detections, args.action, args.quarantine_dir.resolve())

    report = ScanReport(
        generated_at=datetime.now(timezone.utc).isoformat(),
        target=str(target),
        engines=engines,
        files_scanned=files_scanned,
        detections=detections,
        explanation=explanation,
    )
    if args.json_out:
        write_json_report(args.json_out.resolve(), report)
        console.print(f"[green]JSON report saved to {args.json_out.resolve()}[/green]")
    if args.csv_out:
        write_csv_report(args.csv_out.resolve(), detections)
        console.print(f"[green]CSV report saved to {args.csv_out.resolve()}[/green]")
    return 0


def run_create_demo_lab(args: argparse.Namespace) -> int:
    """Create harmless demo files and a matching custom signature database."""

    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    clean_file = directory / "clean_note.txt"
    suspicious_file = directory / "demo_trojan_sample.txt"
    signature_db = directory / "demo_signatures.json"

    clean_file.write_text("This is a clean demo file.\n", encoding="utf-8")
    suspicious_file.write_text(
        "This is not malware. It is a harmless demo file used to test custom antivirus signatures.\n",
        encoding="utf-8",
    )
    digest = sha256_file(suspicious_file)
    signature_db.write_text(
        json.dumps(
            {
                "signatures": [
                    {
                        "sha256": digest,
                        "name": "Demo.Trojan.TestSignature",
                        "type": "trojan",
                        "severity": "HIGH",
                    }
                ]
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    console.print(
        Panel(
            f"Demo lab created at {directory}\n"
            f"Signature DB: {signature_db}\n\n"
            "Test it with:\n"
            f"python .\\simple_antivirus_scanner.py scan {directory} --engine local --signature-db {signature_db} --action ask",
            title="Demo Lab Ready",
            border_style="green",
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build CLI parser."""

    parser = argparse.ArgumentParser(description="Simple antivirus-style scanner for defensive use.")
    subparsers = parser.add_subparsers(dest="command")

    status = subparsers.add_parser("status", help="Show available antivirus engines.")
    status.set_defaults(func=run_status)

    update = subparsers.add_parser("update", help="Update ClamAV or Windows Defender signatures.")
    update.add_argument(
        "--engine",
        default="auto",
        help="auto, local, clamav, avast, kaspersky, defender, all, or comma-separated.",
    )
    update.add_argument("--timeout", type=int, default=900, help="Update timeout in seconds.")
    update.set_defaults(func=run_update)

    scan = subparsers.add_parser("scan", help="Scan a file or folder.")
    scan.add_argument("target", type=Path, help="File or folder to scan.")
    scan.add_argument(
        "--engine",
        default="auto",
        help="auto, local, clamav, avast, kaspersky, defender, all, or comma-separated.",
    )
    scan.add_argument("--signature-db", type=Path, help="Optional custom SHA-256 signature JSON file.")
    scan.add_argument("--max-size-mb", type=int, default=DEFAULT_MAX_SIZE_MB, help="Max file size for local scanning.")
    scan.add_argument("--timeout", type=int, default=1800, help="External engine timeout in seconds.")
    scan.add_argument(
        "--action",
        choices=["ask", "quarantine", "delete", "ignore"],
        default="ask",
        help="What to do with detections after the scan. Default: ask.",
    )
    scan.add_argument("--quarantine-dir", type=Path, default=DEFAULT_QUARANTINE_DIR, help="Quarantine folder.")
    scan.add_argument("--json-out", type=Path, help="Save JSON report.")
    scan.add_argument("--csv-out", type=Path, help="Save CSV report.")
    scan.set_defaults(func=run_scan)

    demo = subparsers.add_parser("create-demo-lab", help="Create harmless test files and a custom signature DB.")
    demo.add_argument("--directory", type=Path, default=Path("demo_lab"), help="Demo lab output directory.")
    demo.set_defaults(func=run_create_demo_lab)

    return parser


def main() -> int:
    """CLI entry point."""

    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user.[/yellow]")
        raise SystemExit(130)
