#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
import json
from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # encrypting it with AES and then RSA + signing
    keysPlural = [] # 0 -> AES, 1 -> RSA
    with open('secret_build_output.txt', 'rb') as keyLAND:
        keysPlural = keyLAND.reads()

    #generate iv
    cipher = AES.new(keysPlural[0], AES.MODE_CBC)
    iv = cipher.iv

    # write iv to header
    with open('skeys.h', 'wb') as headerfile:
        file.write(iv)
        
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


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
