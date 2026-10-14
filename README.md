# Vanguard Antivirus

A Windows-oriented Python antivirus **prototype** with a graphical interface, file scanning, SHA-256 signature matching, EICAR test-pattern recognition, scan logs, and a manual quarantine/restore workflow.

## What it does

- Scans a selected file or recursively scans a selected folder.
- Calculates SHA-256 hashes and checks them against `signatures.json`.
- Detects the harmless EICAR antivirus test pattern.
- Displays clean, detected, and unreadable files in a desktop GUI.
- Lets you manually move detected files into quarantine and restore them later.
- Logs scan and quarantine actions in `logs/vanguard.log`.

## Important limitations

This is an educational prototype, **not a replacement for Microsoft Defender or another maintained security product**. It does not provide kernel-level monitoring, behavioral analysis, cloud reputation, unpacking, memory scanning, exploit prevention, or comprehensive malware signatures. A clean result means only that this scanner found no match in its limited detection methods. Keep Windows Security enabled.

## Requirements

- Windows 10/11 recommended
- Python 3.11+ (Python 3.13 should work)
- Tkinter (normally included with standard Windows Python)

No third-party packages are required.

## Run

1. Extract the project folder.
2. Open `VanguardAntivirus` in PyCharm.
3. Select your Python interpreter.
4. Run `main.py`.
5. Choose **Scan file** or **Scan folder**.

For an initial check, create a text file containing the EICAR test pattern documented by the EICAR organization. Vanguard should mark it as a test-pattern detection. This pattern is harmless when used as a test, but antivirus software may quarantine or remove it. Do not use real malware samples.

## Quarantine notes

Quarantine is manual; the app never automatically moves or deletes detections. A quarantined file is moved into `quarantine/` and tracked in `quarantine/manifest.json`. Restore only if you have independently verified the file is safe. Do not place the project or its quarantine folder in a shared/public directory.

If a move fails across drives, the file operation may need elevated filesystem permissions. Run with normal user privileges first; do not run as Administrator unless there is a specific, understood need.

## Signature database format

`signatures.json` contains exact SHA-256 hashes:

```json
{
  "sha256": {
    "PUT_A_VERIFIED_SHA256_HASH_HERE": "Threat name from trusted source"
  }
}
```

Use only hashes from trustworthy sources and keep attribution/metadata. Never treat an arbitrary hash list from an unknown website as authoritative.

## Project structure

```text
VanguardAntivirus/
├── main.py
├── signatures.json
├── vanguard/
│   ├── __init__.py
│   ├── scanner.py
│   ├── quarantine.py
│   └── logger.py
├── quarantine/
├── logs/
├── tests/
│   └── test_scanner.py
└── README.md
```

## Tests

Run from the project folder:

```bash
python -m unittest discover -s tests -v
```
