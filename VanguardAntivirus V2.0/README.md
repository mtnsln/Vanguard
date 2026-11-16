# Vanguard — Local File Security

Vanguard is a lightweight Windows desktop utility for scanning selected files and folders with a small local detection set. Version 2.0 focuses on a restrained interface, predictable file handling, and transparent reporting.

## Features

- Scan one file or recursively scan a selected folder.
- SHA-256 hashing with exact-match local signatures.
- Recognition of the harmless EICAR antivirus test marker.
- Live scan results with status, file size, reason, and hash.
- Stop a running scan.
- Filter results by detected, clean, and error.
- Manually move selected detections to quarantine.
- Restore quarantined files to a user-selected location after confirmation.
- Export scan results to CSV.
- Rotating local application log.
- No cloud upload and no third-party Python dependencies.

## Important security note

Vanguard is an educational local scanner, **not a replacement for Microsoft Defender or another maintained endpoint-security product**. It does not provide real-time protection, kernel monitoring, behavioral analysis, memory scanning, cloud reputation, unpacking, exploit prevention, or a comprehensive malware signature database.

A `CLEAN` result means only that Vanguard did not find a match in its current local detection methods. It is not proof that a file is safe. Keep Windows Security enabled and up to date. Do not use live malware samples for testing.

## Requirements

- Windows 10/11 recommended
- Python 3.11 or newer
- Tkinter (included with most standard Windows Python installations)

No third-party packages are required.

## Run from source

1. Extract this folder.
2. Open a terminal in the project directory.
3. Run:

   ```bash
   python main.py
   ```

The app stores its logs and quarantine data in the user's home directory under `.vanguard`, rather than inside the source folder.

## Run tests

From the project root:

```bash
python -m unittest discover -s tests -v
```

## Signature database

`signatures.json` contains exact SHA-256 signatures:

```json
{
  "sha256": {
    "64_CHARACTER_SHA256_HASH": "Documented detection label"
  }
}
```

Only add hashes from trusted, documented sources. Keep source and licensing information when maintaining a signature set. A random hash list from an unknown website should not be treated as authoritative.

## Quarantine

Quarantine is manual. Vanguard never automatically moves or deletes detections. Before moving a file, it recalculates its hash and compares it with the scan result to reduce the risk of quarantining a file that changed after scanning. Restoring a file requires confirmation and an integrity check.

The quarantine is stored locally at:

```text
%USERPROFILE%\\.vanguard\\quarantine
```

Restore only if you have independently verified that the file is safe.

## Project structure

```text
Vanguard-Enhanced/
├── main.py
├── signatures.json
├── requirements.txt
├── README.md
├── vanguard/
│   ├── __init__.py
│   ├── scanner.py
│   ├── quarantine.py
│   └── logger.py
└── tests/
    └── test_scanner.py
```

## Design direction

The interface intentionally uses a compact graphite palette, restrained green status accents, clear hierarchy, and native desktop controls. It avoids decorative gradients and oversized dashboard widgets in favor of readable operational information.
