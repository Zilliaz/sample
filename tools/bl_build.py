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

# New imports
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")


def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

    # Creating aesKEY
    aesKEY = get_random_bytes(16)

    # Generate IV
    cipher = AES.new(aesKEY, AES.MODE_CBC)
    IV = cipher.iv

    # Sending aesKEY to 'secret_build_output.txt' for 'fw_protect.py'
    q = open("secret_build_output.txt", 'wb')
    q.write(aesKEY)
    q.close()

    # Sending IV to 'secret_IV.txt' for 'fw_protect.py'
    s = open("secret_IV.txt", 'wb')
    s.write(IV)
    s.close()

    # Sending aesKEY and IV to 'skeys.h' for 'bootloader.c'
    f = open('../bootloader/src/skeys.h', 'w')

    f.write("#ifndef SKEYS_H")
    f.write("\n")
    f.write("#define SECRETS_H")
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
