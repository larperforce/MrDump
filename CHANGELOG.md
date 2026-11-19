# Changelog

## 0.4.0
- Rebuilt the terminal UI around the classic MrDump layout and added independent PE Analysis, ZIP Analysis, ClamAV, Threat Intel, Vulnerabilities, Network, Reports, and Security tabs.
- Removed user-facing JSON report export; Reports now saves readable `.txt` files only.
- Added exclusive report creation to prevent overwriting the inspected file or any existing file.
- Added MP4 / ISO Base Media identification.
- Added bounded sampling for files larger than 128 MiB while hashing the complete file with SHA-256.
- Improved run.bat quote handling and made the interactive UI the default mode.
