"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import os
from pathlib import Path
from loguru import logger


def bytes_to_c_array(byte_data: bytes) -> str:
    """Converts bytes to a C-style static array."""
    return ", ".join(f"0x{b:02X}" for b in byte_data)


def gen_secrets(channels: list[int]) -> str:
    """Generate the contents of the secrets header file.

    This will be used in the Encoder, `ectf25_design.gen_subscription`, 
    and the build process of the decoder.

    :param channels: List of channel numbers that will be valid in this deployment.
                     Channel 0 is the emergency broadcast, which will always be valid
                     and will NOT be included in this list.

    :returns: String containing the contents of the `secrets.h` file.
    """
    # Generate a random AES key (16 bytes for AES-128, 32 bytes for AES-256)
    aes_key = os.urandom(16)  # 16 bytes = 128-bit key

    # Generate channel-specific keys
    channel_keys = {0: os.urandom(16)}  # Emergency broadcast channel key
    for channel in channels:
        channel_keys[channel] = os.urandom(16)

    # Start building the C header file content
    header_content = """#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

// AES Encryption Key
static const uint8_t AES_KEY[16] = { """ + bytes_to_c_array(aes_key) + """ };

// Channel-Specific Keys
"""

    for channel, key in channel_keys.items():
        header_content += f"static const uint8_t CHANNEL_{channel}_KEY[16] = {{ {bytes_to_c_array(key)} }};\n"

    header_content += "\n#endif // SECRETS_H\n"

    return header_content


def parse_args():
    """Define and parse the command-line arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Force creation of the secrets file, overwriting the existing file",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets header file to be created",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Supported channels. Channel 0 (broadcast) is always valid and will not"
        " be provided in this list",
    )
    return parser.parse_args()


def main():
    """Main function of `gen_secrets.py`.

    This function generates a secrets header file that can be included
    in embedded C programs.
    """
    # Parse the command line arguments
    args = parse_args()

    secrets_header = gen_secrets(args.channels)

    # Print generated secrets for debugging
    logger.debug(f"Generated secrets header:\n{secrets_header}")

    # Open the file, erroring if the file exists unless the --force flag is used
    with open(args.secrets_file, "w" if args.force else "x") as f:
        f.write(secrets_header)

    # Log success message
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
