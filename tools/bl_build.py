#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess
import json
from base64 import b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

# const uint8_t KEY_AYEEES[16];
# const uint8_t KEY_ARESSAY[256];

    aesKEY = get_random_bytes(16)
    f = open("skeys.h", 'w')
    # need to convert to bytes, add {}, etc.
    f.write("const uint8_t KEY_AYEEES[16] = {")
    for i in range(15):
        f.write(aesKEY[i]) # AES KEY
        f.write(", ")
    f.write(aesKEY[15])
    f.write("};")
    f.write("\n")
    
    key_areessay = RSA.generate(2048)
    rkey = key_areessay.key('PEM')
    # need to convert to bytes, add {}, etc.
    f.write("const uint8_t KEY_ARESSAY[256] = {")
    for i in range(255):
        f.write(rkey[i]) # RSA Key
        f.write(", ")
    f.write(aesKEY[255])
    f.write("};")
    f.close()

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    copy_initial_firmware(firmware_path)
    make_bootloader()