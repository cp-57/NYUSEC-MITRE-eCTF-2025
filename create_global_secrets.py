import argparse
import os
import json
from pathlib import Path
from loguru import logger


def bytes_to_c_array(hex_string: str) -> str:
    """Converts a hex string to a C-style static array."""
    byte_data = bytes.fromhex(hex_string)
    return ", ".join(f"0x{b:02X}" for b in byte_data)


def gen_secrets(global_secrets_path: Path) -> str:
    """Generate the contents of the secrets header file from a JSON secrets file.

    :param global_secrets_path: Path to the JSON secrets file.

    :returns: String containing the contents of the `secrets.h` file.
    """
    # Load the global secrets JSON file
    try:
        with open(global_secrets_path, "r") as f:
            secrets_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Failed to read or parse secrets file: {e}")
        exit(1)

    chacha_key = secrets_data["chacha_key"]
    channel_keys = secrets_data["channel_keys"]
    num_channels = len(channel_keys)  # Get actual number of keys

    # Start building the C header file content
    header_content = f"""#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

#define MAX_CHANNEL_COUNT {num_channels}

// ChaCha Encryption Key
static const uint8_t CHACHA_KEY[32] = {{ {bytes_to_c_array(chacha_key)} }};

// Structure for channel keys
typedef struct {{
    uint32_t channel;
    uint8_t key[32];
}} channel_key_t;

// List of channel keys
static const channel_key_t CHANNEL_KEYS[MAX_CHANNEL_COUNT] = {{
"""

    for channel, key in channel_keys.items():
        header_content += f"    {{ {channel}, {{ {bytes_to_c_array(key)} }} }},\n"

    header_content += """};

#endif // SECRETS_H
"""

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
        "global_secrets",
        type=Path,
        help="Path to the global secrets JSON file.",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Path to the secrets header file to be created.",
    )
    return parser.parse_args()


def main():
    """Main function to generate the secrets header file."""
    # Parse the command line arguments
    args = parse_args()

    secrets_header = gen_secrets(args.global_secrets)

    # Print generated secrets for debugging
    logger.debug(f"Generated secrets header:\n{secrets_header}")

    # Open the file, erroring if the file exists unless the --force flag is used
    with open(args.secrets_file, "w" if args.force else "x") as f:
        f.write(secrets_header)

    # Log success message
    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")


if __name__ == "__main__":
    main()
