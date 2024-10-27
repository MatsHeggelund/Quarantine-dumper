# Quarantine-dumper

`Quarantine-dumper` is a Python script for extracting quarantined files from Windows Defender. It decrypts quarantined files stored in the Windows Defender quarantine format, useful for threat intelligence or capture-the-flag (CTF) purposes. 

The script can target an entire quarantine directory or a specific GUID quarantine file, outputting the recovered files either to the console or as a `.tar` archive.


## Installation

Clone the repository and navigate to the folder:

```bash
git clone https://github.com/MatsHeggelund/Quarantine-dumper.git
cd Quarantine-dumper
```

## Usage

```
usage: quarantine-dumper.py [-h] (--rootdir ROOTDIR | --file FILE) [-d]

Dump quarantined files from Windows Defender

options:
  -h, --help            show this help message and exit
  --rootdir ROOTDIR, -r ROOTDIR
                        Path to the quarantine root directory
  --file FILE, -f FILE  Path to a single GUID quarantine file (relative or absolute)
  -d, --dump            Dump all entries into a tar archive (quarantine.tar)

Examples:
  To process a quarantine directory and list entries:
    python quarantine-dumper.py --rootdir "Quarantine"
  
  To dump all quarantined files from a directory into a tar archive:
    python quarantine-dumper.py --rootdir "Quarantine" --dump
  
  To process a specific GUID file within the quarantine directory and list entries:
    python quarantine-dumper.py --file "Quarantine/Entries/{GUID}"
  
  To dump a specific GUID file into a tar archive:
    python quarantine-dumper.py --file "Quarantine/Entries/{GUID}" --dump
```

## Example

Given:

```
├── Quarantine
│   ├── Entries
│   │   └── {61008CF3-0000-0000-6011-E57F8319243B}
│   ├── ResourceData
│   │   └── ...
│   │       └── ...
│   └── Resources
│       └── ...
│           └── ...
```

You can do the following:

```
└─$ python3 quarantine-dumper.py -r Quarantine       
2024-08-27 05:17:32.362718 Virus:DOS/Test_File \\?\C:\Users\User\Downloads\malicious.ps1

└─$ python3 quarantine-dumper.py -r Quarantine --dump                                          
Exporting malicious.ps1
File 'quarantine.tar' successfully created
                                                                                                                                                                         
└─$ python3 quarantine-dumper.py -f Quarantine/Entries/\{61008CF3-0000-0000-6011-E57F8319243B\} 
2024-08-27 05:17:32.362718 Virus:DOS/Test_File \\?\C:\Users\User\Downloads\malicious.ps1
                                                                                                                                                                                                                  
└─$ python3 quarantine-dumper.py -f Quarantine/Entries/\{61008CF3-0000-0000-6011-E57F8319243B\} --dump
Exporting malicious.ps1
File 'quarantine.tar' successfully created
```

## Features

- Supports processing either a whole quarantine directory or a single quarantined file by specifying its GUID.
- Extracts and decrypts quarantined files using Windows Defender's specific encryption key.
- Outputs quarantined files in a `.tar` archive (`quarantine.tar`) for easy retrieval.
  
## Prerequisites

- Python 3.x
- Compatible with systems that can access the Windows Defender quarantine folder (e.g., when using a Windows Subsystem for Linux (WSL) or with an extracted Defender directory on Linux).

## Credit

Windows Defender Quarantined file dumper - Inspired by https://github.com/knez/defender-dump
