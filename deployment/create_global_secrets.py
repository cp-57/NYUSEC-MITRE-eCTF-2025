import json
import os

def format_key_c_array(hex_key):
    """Converts a hex string to a comma-separated C-style array."""
    byte_data = bytes.fromhex(hex_key) 
    return ", ".join(f"0x{b:02X}" for b in byte_data)

def generate_secrets_h(json_data):
    chacha_key = json_data["chacha_key"]
    channel_keys = json_data["channel_keys"]
    num_channels = len(channel_keys)

    header_content = f"""#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

#define MAX_CHANNEL_COUNT {num_channels}

// ChaCha Encryption Key
static const uint8_t CHACHA_KEY[32] = {{ {format_key_c_array(chacha_key)} }};

// Structure for channel keys
typedef struct {{
    uint32_t channel;
    uint8_t key[32];
}} channel_key_t;

// Array of channel keys
static const channel_key_t CHANNEL_KEYS[MAX_CHANNEL_COUNT] = {{
"""
    for channel, key in channel_keys.items():
        header_content += f"    {{ {channel}, {{ {format_key_c_array(key)} }} }},\n"

    header_content += """};

#endif // SECRETS_H
"""

    return header_content

input_file_path = "/global.secrets"
output_file_path = "/decoder/inc/secrets.h"

# Check if the input file exists
if not os.path.exists(input_file_path):
    print(f"Error: File '{input_file_path}' not found!")
    exit(1)

# Load JSON and generate header file
with open(input_file_path, "r") as json_file:
    json_data = json.load(json_file)

secrets_h_content = generate_secrets_h(json_data)

# Save to file
with open(output_file_path, "w") as file:
    file.write(secrets_h_content)

print(f"Generated '{output_file_path}' successfully!")
