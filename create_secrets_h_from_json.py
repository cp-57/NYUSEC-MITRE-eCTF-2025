import json
import os

# Function to format a hex key as a C array
def format_key_c_array(hex_key):
    return ", ".join(f"0x{hex_key[i:i+2]}" for i in range(0, len(hex_key), 2))

# Function to generate the C header file from JSON input
def generate_secrets_h(json_data):
    aes_key = json_data["aes_key"]
    channel_keys = json_data["channel_keys"]
    hmac_keys = json_data["hmac_keys"]  # Get HMAC keys from JSON

    header_content = """#ifndef SECRETS_H
#define SECRETS_H

#include <stdint.h>

// AES Encryption Key
static uint8_t AES_KEY[16] = { """ + format_key_c_array(aes_key) + " };\n\n"

    # Add channel keys
    for channel, key in channel_keys.items():
        header_content += f"// Channel {channel} Key\n"
        header_content += f"static const uint8_t CHANNEL_{channel}_KEY[16] = {{ {format_key_c_array(key)} }};\n\n"

    # Add HMAC keys
    header_content += "// Channel-Specific HMAC Keys\n"
    for channel, key in hmac_keys.items():
        header_content += f"static const uint8_t CHANNEL_{channel}_HMAC[32] = {{ {format_key_c_array(key)} }};\n\n"
    
    # Add default HMAC key for any channels not explicitly defined
    if "default" in hmac_keys:
        default_hmac = hmac_keys["default"]
    else:
        # Generate a default HMAC key if none exists
        default_hmac = os.urandom(32).hex()
        
    header_content += f"static const uint8_t DEFAULT_HMAC[32] = {{ {format_key_c_array(default_hmac)} }};\n\n"

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

# Check if hmac_keys exist in the JSON, if not, display an error
if "hmac_keys" not in json_data:
    print("Error: 'hmac_keys' not found in the JSON file!")
    print("Make sure you've updated your gen_secrets.py script to generate HMAC keys.")
    exit(1)

secrets_h_content = generate_secrets_h(json_data)

# Save to file
with open(output_file_path, "w") as file:
    file.write(secrets_h_content)

print(f"Generated '{output_file_path}' successfully!")