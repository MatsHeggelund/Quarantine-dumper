# Quarantine-dumper

`Quarantine-dumper` is a Python script for extracting quarantined files from Windows Defender. It decrypts quarantined files stored in the Windows Defender quarantine format, useful for threat intelligence or capture-the-flag (CTF) purposes. 

The script can target an entire quarantine directory or a specific GUID quarantine file, outputting the recovered files either to the console or as a `.tar` archive.

## Features

- Supports processing either a whole quarantine directory or a single quarantined file by specifying its GUID.
- Extracts and decrypts quarantined files using Windows Defender's specific encryption key.
- Outputs quarantined files in a `.tar` archive (`quarantine.tar`) for easy retrieval.
  
## Prerequisites

- Python 3.x
- Compatible with systems that can access the Windows Defender quarantine folder (e.g., when using a Windows Subsystem for Linux (WSL) or with an extracted Defender directory on Linux).

## Installation

Clone the repository and navigate to the folder:

```bash
git clone https://github.com/MatsHeggelund/Quarantine-dumper.git
cd DefenderDump
```

## Credit

Windows Defender Quarantined file dumper - Inspired by https://github.com/knez/defender-dump
