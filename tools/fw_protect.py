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
from Crypto.Util.Padding import pad
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # encrypting it with AES and then RSA + signing
    with open('secret_build_output.txt', 'rb') as keyLAND:
        keyAES = keyLAND.read()

    ct = b""
    for chunk in [firmware[i:i + 16] for i in range(0, len(firmware), 16)]:
        # generate iv
        cipher = AES.new(keyAES, AES.MODE_CBC)
        IV = cipher.iv
        f = open('../bootloader/src/skeys.h', 'w') # storing iv in skeys.h
        f.write("#ifndef SKEYS_H")
        f.write("\n")
        f.write("#define SECRETS_H")
        f.write("\n")
        f.write("const uint8_t IV[16] = {")
        for i in range (15):
            f.write(str(IV[i]))
            f.write(", ")
        f.write(str(IV[15]))
        f.write("};")
        f.write("\n")
        f.write("#endif")
        f.close()
        
        if len(chunk) < 16:
            padded = pad(chunk, 16)
        else:
            padded = chunk
        
        ct += cipher.encrypt(padded) # AESs

    k =  open(outfile, 'w+') 
    k.write("aaaa") # should be metadata (4 bytes)
    for chunk in [ct[i:i + 238] for i in range(0, len(ct), 238)]:      
        k.write("aa") # should be length, 2 
        k.write(str(IV)) # should be length 16
        k.write(str(chunk)) # 238 bytes
    k.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
