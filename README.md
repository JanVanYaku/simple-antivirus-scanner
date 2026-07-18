# Simple Antivirus Scanner

A beginner-friendly Python antivirus-style scanner for defensive use. It scans files or folders, reports detections in a table, explains the results, then asks whether to quarantine, delete, or ignore detected files.

This project uses real local signature engines when they are available:

- **ClamAV** through `clamscan`, using the ClamAV signature database.
- **Avast** through the installed Avast command-line scanner `ashCmd.exe`, using Avast's installed VPS definitions.
- **Kaspersky** through the installed Kaspersky command-line tools `avp.com` or `kescli.exe`, using Kaspersky's installed databases.
- **Microsoft Defender** on Windows through PowerShell Defender cmdlets.
- **Local signatures** for the harmless EICAR test pattern and optional custom SHA-256 signature databases.

Avast and Kaspersky databases are proprietary. This app does not download, copy, unpack, or redistribute those databases. Install the official product, keep it licensed and updated, and this app can call the vendor scanner so the vendor engine uses its own signatures.

No antivirus can guarantee that a machine is completely clean. Keep your real-time antivirus enabled and signatures updated.

## Features

- Scan a file or folder.
- Use `auto`, `local`, `clamav`, `avast`, `kaspersky`, `defender`, `all`, or comma-separated engines.
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

If Avast or Kaspersky is installed in a non-standard location, set one of these environment variables before scanning:

```powershell
$env:CLAMAV_CLAMSCAN_PATH="C:\Program Files\ClamAV\clamscan.exe"
$env:CLAMAV_FRESHCLAM_PATH="C:\Program Files\ClamAV\freshclam.exe"
$env:AVAST_ASHCMD_PATH="C:\Program Files\AVAST Software\Avast\ashCmd.exe"
$env:AVAST_ASHUPD_PATH="C:\Program Files\AVAST Software\Avast\ashUpd.exe"
$env:KASPERSKY_AVP_PATH="C:\Program Files\Kaspersky Lab\Your Product\avp.com"
$env:KASPERSKY_KESCLI_PATH="C:\Program Files\Kaspersky Lab\Your Product\kescli.exe"
```

Check whether the Avast command-line tools actually exist:

```powershell
Test-Path "C:\Program Files\AVAST Software\Avast\ashCmd.exe"
Test-Path "C:\Program Files\AVAST Software\Avast\ashUpd.exe"
```

`AVAST_ASHCMD_PATH` is used for scans. `AVAST_ASHUPD_PATH` is used for updates. If `ashCmd.exe` is found, the app also checks the same folder for `ashUpd.exe` automatically.

Avast One may install into:

```powershell
C:\Program Files\Avast Software\Suite
```

That folder may include `ashUpd.exe` for updates but not `ashCmd.exe` for command-line scans. In that case Avast updates can work, but Avast scanning through this wrapper is unavailable unless your Avast edition provides `ashCmd.exe`.

If ClamAV is found but Windows reports `WinError 216` or a "Machine Type Mismatch" popup, the installed ClamAV executable does not match your Windows architecture. For example, an `ARM64` ClamAV build will not run on an `AMD64` Windows PC. Install the matching ClamAV build for your machine, or set `CLAMAV_CLAMSCAN_PATH` and `CLAMAV_FRESHCLAM_PATH` to compatible executables.

The app checks the Windows executable type before launching ClamAV, so incompatible ClamAV installs are reported in the status table instead of repeatedly opening the Windows mismatch popup.

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

Update Avast virus definitions if Avast is installed:

```powershell
python .\simple_antivirus_scanner.py update --engine avast
```

If Avast returns `WinError 740`, open PowerShell as Administrator and run the update command again.

Update Kaspersky databases if Kaspersky is installed:

```powershell
python .\simple_antivirus_scanner.py update --engine kaspersky
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

Scan with Avast:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine avast
```

Scan with Kaspersky:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine kaspersky
```

Scan with several engines:

```powershell
python .\simple_antivirus_scanner.py scan C:\Users\YourName\Downloads --engine clamav,avast,kaspersky,defender
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

## Vendor Command-Line Notes

- ClamAV must be installed separately. The app uses `clamscan` for scans and `freshclam` for updates.
- Avast Business/Small Office products expose `ashCmd.exe` for scans and `ashUpd.exe vps` for definition updates: https://businesshelp.avast.com/Content/Products/AfB_Antivirus/ConfiguringSettings/CommandLineUpdatesScans.htm
- Kaspersky products expose `avp.com SCAN` or `kescli --opswat Scan` depending on product/version: https://support.kaspersky.com/kes-for-windows/12.5/181236 and https://support.kaspersky.com/kes-for-windows/12.9/213709
- Some vendor tools may require Administrator PowerShell or product policy settings that allow local command-line scans.
