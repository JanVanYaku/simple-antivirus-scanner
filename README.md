# Simple Antivirus Scanner

A beginner-friendly Python antivirus-style scanner for defensive use. It scans files or folders, reports detections in a table, explains the results, then asks whether to quarantine, delete, or ignore detected files.

This project uses real local signature engines when they are available:

- **ClamAV** through `clamscan`, using the ClamAV signature database.
- **Microsoft Defender** on Windows through PowerShell Defender cmdlets.
- **Local signatures** for the harmless EICAR test pattern and optional custom SHA-256 signature databases.

No antivirus can guarantee that a machine is completely clean. Keep your real-time antivirus enabled and signatures updated.

## Features

- Scan a file or folder.
- Use `auto`, `local`, `clamav`, `defender`, `all`, or comma-separated engines.
- Show detections with engine, severity, threat name, malware type, file path, and evidence.
- Ask what to do after scanning: quarantine, delete, or ignore.
- Quarantine files with metadata.
- Update ClamAV or Defender signatures where available.
- Export JSON and CSV reports.
- Create a harmless demo lab for testing.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Check Engines

```powershell
python .\simple_antivirus_scanner.py status
```

## Update Signatures

Update the available engine:

```powershell
python .\simple_antivirus_scanner.py update --engine auto
```

Update Defender on Windows:

```powershell
python .\simple_antivirus_scanner.py update --engine defender
```

Update ClamAV if installed:

```powershell
python .\simple_antivirus_scanner.py update --engine clamav
```

## Scan

Scan a folder and ask what to do with detections:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine auto
```

Scan a whole drive:

```powershell
python .\simple_antivirus_scanner.py scan C:\ --engine auto
```

Scan with Windows Defender:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine defender
```

Scan with ClamAV:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine clamav
```

Scan and automatically quarantine detections:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine auto --action quarantine
```

Save reports:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine auto --json-out .\reports\scan.json --csv-out .\reports\scan.csv
```

## Safe Demo Lab

Create harmless demo files and a custom SHA-256 signature database:

```powershell
python .\simple_antivirus_scanner.py create-demo-lab --directory .\demo_lab
```

Scan the demo lab:

```powershell
python .\simple_antivirus_scanner.py scan .\demo_lab --engine local --signature-db .\demo_lab\demo_signatures.json
```

The demo detection is not real malware. It only proves the scanner, table, explanation, report, and action workflow are working.

## Custom Signature Database

You can provide your own SHA-256 signatures:

```json
{
  "signatures": [
    {
      "sha256": "example_sha256_hash",
      "name": "Example.Trojan.Signature",
      "type": "trojan",
      "severity": "HIGH"
    }
  ]
}
```

Then scan with:

```powershell
python .\simple_antivirus_scanner.py scan .\samples --engine local --signature-db .\signatures.json
```

## Understanding Results

- `CLEAN` means no selected engine reported a detection in the scanned files.
- `TEST` usually means the harmless EICAR antivirus test pattern.
- `HIGH` means the engine matched a known malware or custom signature.
- `Quarantine` is usually safest first because it isolates the file while keeping it for review.
- `Delete` is permanent and should only be used when you are confident the file is unwanted.
- `Ignore` leaves the file unchanged.

For serious incidents, disconnect the machine from the network, preserve logs, and use a trusted incident-response process.
