#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct

# New imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad


def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Loads in aesKEY from 'secret_build_output.txt'
    with open('secret_build_output.txt', 'rb') as fq:
        aesKEY = fq.read()

    # Loads in IV from 'secret_IV.txt'
    with open('secret_IV.txt', 'rb') as fs:
        IV = fs.read()

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Encrypting firmware into ct
    ct = b"" # Variable for encrypted firmware
    padded_chunk = b""
    for chunk in [firmware_and_message[i:i + 16] for i in range(0, len(firmware_and_message), 16)]:
        cipher = AES.new(aesKEY, AES.MODE_CBC, iv = IV)

        # Padding chunks since AES only encrypts in bytes of 16
        if len(chunk) < 16:
            padded_chunk = pad(chunk, 16)
        else:
            padded_chunk = chunk

        ct += cipher.encrypt(padded_chunk)

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + ct

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile:
        outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
