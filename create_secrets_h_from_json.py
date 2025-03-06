import json
import os

# Function to format a hex key as a C array
def format_key_c_array(hex_key):
    return ", ".join(f"0x{hex_key[i:i+2]}" for i in range(0, len(hex_key), 2))

# Function to generate the C header file from JSON input
def generate_secrets_h(json_data):
    aes_key = json_data["chacha_key"]
    channel_keys = json_data["channel_keys"]

    header_content = """#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

// AES Encryption Key
static uint8_t CHACHA_KEY[32] = { """ + format_key_c_array(aes_key) + " };\n\n"

    # Add channel keys
    for channel, key in channel_keys.items():
        header_content += f"// Channel {channel} Key\n"
        header_content += f"static const uint8_t CHANNEL_{channel}_KEY[32] = {{ {format_key_c_array(key)} }};\n\n"

    header_content += "#endif // SECRETS_H"

    return header_content

# Read JSON from secrets/secrets.json
input_file_path = "secrets/secrets.json"
output_file_path = "secrets.h"

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
