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

# Jayden's suggestion for sending IV
# def arrayize(binary_string):
#     return '{' + ','.join([hex(char) for char in binary_string]) + '}'
#     with open('./src/secrets.h', 'w') as f:
#         f.write("#ifndef SECRETS_H\n")
#         f.write("#define SECRETS_H\n")
#         f.write("const uint8_t IV[10] = " + arrayize(iv) + ";\n")
#         f.write("#endif")

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    # 26-Shift Caesar Cypher
    # LETTERS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    # s = 26
    # julius = ""
    # # transverse the plain text
    # for i in range(len(firmware)):
    #     char = firmware[i]
    #     # Encrypt uppercase characters in plain text
    #     if (char.isupper()):
    #         julius += chr((ord(char) + s-65) % 26 + 65)
    #     # Encrypt lowercase characters in plain text
    #     elif (char.islower()):
    #         julius += chr((ord(char) + s - 97) % 26 + 97)
    #     else:
    #         julius += chr((ord(char)))
    # firmware = julius

    # AES Encryption:
    with open('secret_build_output.txt', 'rb') as keyLAND:
        keyAES = keyLAND.read()

    ct = b""
    ivy_length = len(firmware) / 16 + 1
    ivy = []
    ivy = [{} for i in range (ivy_length)]
    for chunk in [firmware[i:i + 240] for i in range(0, len(firmware), 240)]:
        # generate iv
        cipher = AES.new(keyAES, AES.MODE_CBC)
        IV = cipher.iv
        ivy[i] = IV
        # arrayize(IV)

        # pads last chunk to 240
        if len(chunk) < 240:
            padded = pad(chunk, 240)
        else:
            padded = chunk
        
        # actually encrypts each chunk, adds to ct
        ct += cipher.encrypt(padded) # AESs

    metadata = struct.pack('<HH', version, len(firmware)) # Do we need to do len(ct) or len(firmware) for 'size'?

    # Writes frame to fw_update.py
    k = open(outfile, 'wb+')
    k.write(metadata) # should be metadata (version/size) [4 bytes]
    for chunk in [ct[i:i + 240] for i in range(0, len(ct), 240)]: 
        placeholder = len(chunk) # length
        k.write(placeholder.to_bytes()) # writing over length [2 bytes] 
        k.write(ivy[i]) # writing over IV [16 bytes]
        k.write(chunk) # writing over ciphertext [240 bytes]
    k.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)
"""
⢀⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⠀⣠⣤⣶⣶
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠀⠀⢰⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⣀⣀⣾⣿⣿⣿⣿
⣿⣿⣿⣿⣿⡏⠉⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿
⣿⣿⣿⣿⣿⣿⠀⠀⠀⠈⠛⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠁⠀⣿
⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠙⠿⠿⠿⠻⠿⠿⠟⠿⠛⠉⠀⠀⠀⠀⠀⣸⣿
⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣴⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠠⣴⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡟⠀⠀⢰⣹⡆⠀⠀⠀⠀⠀⠀⣭⣷⠀⠀⠀⠸⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠈⠉⠀⠀⠤⠄⠀⠀⠀⠉⠁⠀⠀⠀⠀⢿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⢾⣿⣷⠀⠀⠀⠀⡠⠤⢄⠀⠀⠀⠠⣿⣿⣷⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⡀⠉⠀⠀⠀⠀⠀⢄⠀⢀⠀⠀⠀⠀⠉⠉⠁⠀⠀⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿
"""