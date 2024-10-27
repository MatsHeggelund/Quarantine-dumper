#!/usr/bin/env python3

'''
Dumps quarantined files from Windows Defender

Windows and Linux support

Inspired by https://github.com/knez/defender-dump
'''

import io
import struct
import argparse
import datetime
import pathlib
import tarfile
import sys

from collections import namedtuple

file_record = namedtuple("file_record", "path hash detection filetime")

def mse_ksa():
    # hardcoded key obtained from mpengine.dll
    key = [
        0x1E, 0x87, 0x78, 0x1B, 0x8D, 0xBA, 0xA8, 0x44, 0xCE, 0x69,
        0x70, 0x2C, 0x0C, 0x78, 0xB7, 0x86, 0xA3, 0xF6, 0x23, 0xB7,
        0x38, 0xF5, 0xED, 0xF9, 0xAF, 0x83, 0x53, 0x0F, 0xB3, 0xFC,
        0x54, 0xFA, 0xA2, 0x1E, 0xB9, 0xCF, 0x13, 0x31, 0xFD, 0x0F,
        0x0D, 0xA9, 0x54, 0xF6, 0x87, 0xCB, 0x9E, 0x18, 0x27, 0x96,
        0x97, 0x90, 0x0E, 0x53, 0xFB, 0x31, 0x7C, 0x9C, 0xBC, 0xE4,
        0x8E, 0x23, 0xD0, 0x53, 0x71, 0xEC, 0xC1, 0x59, 0x51, 0xB8,
        0xF3, 0x64, 0x9D, 0x7C, 0xA3, 0x3E, 0xD6, 0x8D, 0xC9, 0x04,
        0x7E, 0x82, 0xC9, 0xBA, 0xAD, 0x97, 0x99, 0xD0, 0xD4, 0x58,
        0xCB, 0x84, 0x7C, 0xA9, 0xFF, 0xBE, 0x3C, 0x8A, 0x77, 0x52,
        0x33, 0x55, 0x7D, 0xDE, 0x13, 0xA8, 0xB1, 0x40, 0x87, 0xCC,
        0x1B, 0xC8, 0xF1, 0x0F, 0x6E, 0xCD, 0xD0, 0x83, 0xA9, 0x59,
        0xCF, 0xF8, 0x4A, 0x9D, 0x1D, 0x50, 0x75, 0x5E, 0x3E, 0x19,
        0x18, 0x18, 0xAF, 0x23, 0xE2, 0x29, 0x35, 0x58, 0x76, 0x6D,
        0x2C, 0x07, 0xE2, 0x57, 0x12, 0xB2, 0xCA, 0x0B, 0x53, 0x5E,
        0xD8, 0xF6, 0xC5, 0x6C, 0xE7, 0x3D, 0x24, 0xBD, 0xD0, 0x29,
        0x17, 0x71, 0x86, 0x1A, 0x54, 0xB4, 0xC2, 0x85, 0xA9, 0xA3,
        0xDB, 0x7A, 0xCA, 0x6D, 0x22, 0x4A, 0xEA, 0xCD, 0x62, 0x1D,
        0xB9, 0xF2, 0xA2, 0x2E, 0xD1, 0xE9, 0xE1, 0x1D, 0x75, 0xBE,
        0xD7, 0xDC, 0x0E, 0xCB, 0x0A, 0x8E, 0x68, 0xA2, 0xFF, 0x12,
        0x63, 0x40, 0x8D, 0xC8, 0x08, 0xDF, 0xFD, 0x16, 0x4B, 0x11,
        0x67, 0x74, 0xCD, 0x0B, 0x9B, 0x8D, 0x05, 0x41, 0x1E, 0xD6,
        0x26, 0x2E, 0x42, 0x9B, 0xA4, 0x95, 0x67, 0x6B, 0x83, 0x98,
        0xDB, 0x2F, 0x35, 0xD3, 0xC1, 0xB9, 0xCE, 0xD5, 0x26, 0x36,
        0xF2, 0x76, 0x5E, 0x1A, 0x95, 0xCB, 0x7C, 0xA4, 0xC3, 0xDD,
        0xAB, 0xDD, 0xBF, 0xF3, 0x82, 0x53
    ]
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
    return sbox

def rc4_decrypt(data):
    sbox = mse_ksa()
    out = bytearray(len(data))
    i = 0
    j = 0
    for k in range(len(data)):
        i = (i + 1) % 256
        j = (j + sbox[i]) % 256
        tmp = sbox[i]
        sbox[i] = sbox[j]
        sbox[j] = tmp
        val = sbox[(sbox[i] + sbox[j]) % 256]
        out[k] = val ^ data[k]

    return out

def unpack_malware(f):
    decrypted = rc4_decrypt(f.read())
    sd_len = struct.unpack_from('<I', decrypted, 0x8)[0]
    header_len = 0x28 + sd_len
    malfile_len = struct.unpack_from('<Q', decrypted, sd_len + 0x1C)[0]
    malfile = decrypted[header_len:header_len + malfile_len]

    return (malfile, malfile_len)

def dump_entries(quarfile, entries):
    tar = tarfile.open('quarantine.tar', 'w')

    for file_rec in entries:
        if not quarfile.exists():
            print(f"Quarantine file not found: {quarfile}", file=sys.stderr)
            continue

        with open(quarfile, 'rb') as f:
            print(f'Exporting {file_rec.path.name}')
            malfile, malfile_len = unpack_malware(f)

            tarinfo = tarfile.TarInfo(file_rec.path.name)
            tarinfo.size = malfile_len
            tar.addfile(tarinfo, io.BytesIO(malfile))

    tar.close()

    print("File 'quarantine.tar' successfully created")

def get_entry(data):
    # extract path as a null-terminated UTF-16 string
    pos = data.find(b'\x00\x00\x00') + 1
    if pos == 0:
        raise ValueError("Invalid entry format: null terminator not found for path")
    path_str = data[:pos].decode('utf-16le', errors='ignore')

    # normalize the path
    if path_str.startswith('?:\\'):
        path_str = path_str[4:]

    path = pathlib.PureWindowsPath(path_str)

    pos += 4  # skip number of entries field
    type_len = data[pos:].find(b'\x00')
    if type_len == -1:
        raise ValueError("Invalid entry format: null terminator not found for type")
    type = data[pos:pos + type_len].decode('utf-8', errors='ignore')  # get entry Type (UTF-8)
    pos += type_len + 1
    pos += (4 - (pos % 4)) % 4  # skip padding bytes
    pos += 4  # skip additional metadata
    hash = data[pos:pos + 20].hex().upper()

    return (path, hash, type)

def parse_entries_from_directory(basedir):
    results = []
    for guid in basedir.glob('Entries/*'):
        if not guid.is_file():
            continue
        with open(guid, 'rb') as f:
            try:
                header = rc4_decrypt(f.read(0x3c))
                data1_len, data2_len = struct.unpack_from('<II', header, 0x28)

                data1 = rc4_decrypt(f.read(data1_len))
                filetime, = struct.unpack('<Q', data1[0x20:0x28])
                # Convert Windows filetime to datetime
                filetime = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=filetime // 10 - 11644473600000000)
                detection = data1[0x34:].decode('utf-8', errors='ignore')

                data2 = rc4_decrypt(f.read(data2_len))
                cnt = struct.unpack_from('<I', data2)[0]
                offsets = struct.unpack_from('<' + str(cnt) + 'I', data2, 0x4)

                for o in offsets:
                    try:
                        path, hash, type = get_entry(data2[o:])
                        if type.lower() == 'file':
                            results.append(file_record(path, hash, detection, filetime))
                    except Exception as e:
                        print(f"Failed to parse entry at offset {o} in {guid}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Failed to parse GUID file {guid}: {e}", file=sys.stderr)

    return results

def parse_entry_from_file(file_path):
    if not file_path.exists() or not file_path.is_file():
        print(f"Error: The specified file does not exist or is not a file: {file_path}", file=sys.stderr)
        return []

    results = []
    with open(file_path, 'rb') as f:
        try:
            header = rc4_decrypt(f.read(0x3c))
            data1_len, data2_len = struct.unpack_from('<II', header, 0x28)

            data1 = rc4_decrypt(f.read(data1_len))
            filetime, = struct.unpack('<Q', data1[0x20:0x28])
            # Convert Windows filetime to datetime
            filetime = datetime.datetime(1970, 1, 1) + datetime.timedelta(microseconds=filetime // 10 - 11644473600000000)
            detection = data1[0x34:].decode('utf-8', errors='ignore')

            data2 = rc4_decrypt(f.read(data2_len))
            cnt = struct.unpack_from('<I', data2)[0]
            offsets = struct.unpack_from('<' + str(cnt) + 'I', data2, 0x4)

            for o in offsets:
                try:
                    path, hash, type = get_entry(data2[o:])
                    if type.lower() == 'file':
                        results.append(file_record(path, hash, detection, filetime))
                except Exception as e:
                    print(f"Failed to parse entry at offset {o} in {file_path}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"Failed to parse file {file_path}: {e}", file=sys.stderr)

    return results

def main(args):
    if args.rootdir:
        basedir = args.rootdir  # Quarantine root directory

        if not basedir.exists() or not basedir.is_dir():
            print(f"Error: The specified root directory does not exist or is not a directory: {basedir}", file=sys.stderr)
            sys.exit(1)

        entries = parse_entries_from_directory(basedir)

    elif args.file:
        file_path = pathlib.Path(args.file)
        if not file_path.is_absolute():
            file_path = pathlib.Path.cwd() / file_path

        entries = parse_entry_from_file(file_path)

    else:
        print("Error: Either --rootdir or --file must be specified.", file=sys.stderr)
        sys.exit(1)

    if not entries:
        print("No valid entries found. Please check the input path.", file=sys.stderr)
        sys.exit(1)

    if args.dump:
        if args.rootdir:
            # Export quarantine files from directory
            for file_rec in entries:
                quarfile = args.rootdir / 'ResourceData' / file_rec.hash[:2] / file_rec.hash

                if not quarfile.exists():
                    print(f"Quarantine file not found: {quarfile}", file=sys.stderr)
                    continue

                with open(quarfile, 'rb') as f:
                    print(f'Exporting {file_rec.path.name}')
                    malfile, malfile_len = unpack_malware(f)

                    with tarfile.open('quarantine.tar', 'a') as tar:
                        tarinfo = tarfile.TarInfo(file_rec.path.name)
                        tarinfo.size = malfile_len
                        tar.addfile(tarinfo, io.BytesIO(malfile))
            print("File 'quarantine.tar' successfully created")

        elif args.file:
            # Export quarantine file from single file
            tar = tarfile.open('quarantine.tar', 'w')

            for file_rec in entries:
                quarfile = pathlib.Path(args.file)
                if not quarfile.exists():
                    print(f"Quarantine file not found: {quarfile}", file=sys.stderr)
                    continue

                with open(quarfile, 'rb') as f:
                    print(f'Exporting {file_rec.path.name}')
                    malfile, malfile_len = unpack_malware(f)

                    tarinfo = tarfile.TarInfo(file_rec.path.name)
                    tarinfo.size = malfile_len
                    tar.addfile(tarinfo, io.BytesIO(malfile))

            tar.close()
            print("File 'quarantine.tar' successfully created")
    else:
        # Display quarantine files
        detection_max_len = max([len(x.detection) for x in entries], default=0)
        for entry in entries:
            print(entry.filetime, f"{entry.detection:<{detection_max_len}}", entry.path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Dump quarantined files from Windows Defender',
        epilog='''
Examples:
  To process a quarantine directory and list entries:
    python quarantine-dumper.py --rootdir "Quarantine"
  
  To dump all quarantined files from a directory into a tar archive:
    python quarantine-dumper.py --rootdir "Quarantine" --dump
  
  To process a specific GUID file within the quarantine directory and list entries:
    python quarantine-dumper.py --file "Quarantine/Entries/{GUID}"
  
  To dump a specific GUID file into a tar archive:
    python quarantine-dumper.py --file "Quarantine/Entries/{GUID}" --dump
''',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        '--rootdir', '-r', type=pathlib.Path,
        help='Path to the quarantine root directory'
    )
    group.add_argument(
        '--file', '-f', type=str,
        help='Path to a single GUID quarantine file (relative or absolute)'
    )
    parser.add_argument(
        '-d', '--dump', action='store_true',
        help='Dump all entries into a tar archive (quarantine.tar)'
    )

    args = parser.parse_args()
    main(args)
