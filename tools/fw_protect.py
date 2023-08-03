#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct

# new imports
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # Reading in AES key
    with open('secret_build_output.txt', 'rb') as fp:
        aesKEY = fp.read()
    
    # Generating IV
    cipher = AES.new(aesKEY, AES.MODE_CBC)
    IV = cipher.iv

    # Writing aesKEY, IV to skeys.h
    f = open('../bootloader/src/skeys.h', 'w')
    f.write("#ifndef SKEYS_H")
    f.write("\n")
    f.write("#define SKEYS_H")
    f.write("\n")

    f.write("const uint8_t aesKEY[16] = {")
    for i in range (15):
        f.write(hex(aesKEY[i]))
        f.write(", ")
    f.write(hex(aesKEY[15]))
    f.write("};")
    f.write("\n")

    f.write("const uint8_t IV[16] = {")
    for i in range (15):
        f.write(hex(IV[i]))
        f.write(", ")
    f.write(hex(IV[15]))
    f.write("};")
    f.write("\n")

    f.write("#endif")
    f.close()

    # Creating variable to store encrypted firmware
    ct = b""

    # Using for loop since AES only encrypts in multiples of 16-byte chunks
    for chunk in [firmware[i:i + 16] for i in range(0, len(firmware), 16)]:
        # Pads very last chunk
        if len(chunk) < 16:
            padded = pad(chunk, 16)
        else:
            padded = chunk

        # Encrypts each 16-byte chunk, stores in 'ct'
        ct += cipher.encrypt(padded)

    firmware = ct # Since insecureExample uses variable 'firmware'

    # Append null-terminated message to end of firmware
    firmware_and_message = firmware + message.encode() + b'\00'

    # Pack version and size into two little-endian shorts
    metadata = struct.pack('<HH', version, len(firmware))

    # Append firmware and message to metadata
    firmware_blob = metadata + IV + firmware_and_message

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
