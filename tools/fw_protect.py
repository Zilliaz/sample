#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # encrypting it with AES and then RSA + signing
    keysPlural = [] # 0 -> AES, 1 -> RSA
    with open('secret_build_output.txt', 'rb') as keyLAND:
        keysPlural = keyLAND.reads()

    cipher = AES.new(keysPlural[0], AES.MODE_CBC)
    iv = cipher.iv

    for chunk in [firmware[i:i + 252] for i in range(0, len(firmware), 252)]:
        if len(chunk) < 252:
            padded = pad(chunk, 252)
        else:
            padded = chunk
        
        ct = cipher.encrypt(padded) # AES
        h = SHA256.new(ct) # RSA
        signature = pkcs1_15.new(keysPlural[1]).sign(h) # RSA
        answer = h.digest() # RSA

        with open(outfile, 'wb+') as outfile:
            outfile.write(answer)
            outfile.write(signature)

    # failed attempt at encrypting into RSA
    # key = RSA.import_key(open('secret_build_output.txt').read())

    # for chunk in [firmware[i:i + 256] for i in range(0, len(firmware), 256)]:
    #     if len(chunk) < 256:
    #         data = pad(chunk, 256)
    #     else:
    #         data = chunk
    #     print(data)
        
    #     h = SHA256.new(data)
    #     signature = pkcs1_15.new(key).sign(h)

    #     answer = h.digest()
    #     with open(outfile, 'wb+') as outfile:
    #         outfile.write(answer)
    #         outfile.write(signature)

    # # Append null-terminated message to end of firmware
    # firmware_and_message = firmware + message.encode() + b'\00'

    # # Pack version and size into two little-endian shorts
    # metadata = struct.pack('<HH', version, len(firmware))

    # # Append firmware and message to metadata
    # firmware_blob = metadata + firmware_and_message

    # Write firmware blob to outfile
    # with open(outfile, 'wb+') as outfile:
    #     outfile.write(firmware_blob)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)