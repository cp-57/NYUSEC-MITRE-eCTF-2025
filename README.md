# NYUSEC eCTF 2025 - Satellite TV System

## Layout

- `decoder/` - Firmware for the television decoder.
    - `project.mk` - This file defines project specific variables included in the Makefile
    - `Makefile` - This makefile is invoked by the eCTF tools when creating a decoder.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `inc/` - Directory with c header files
    - `src/` - Directory with c source files
    - `wolfssl/` - Location to place wolfssl library for included Crypto Example
- `design/` - Host design elements
    - `ectf25_design/` - Host design source code
        - `encoder.py` - Encodes frames
        - `gen_secrets.py` - Generates shared secrets
        - `gen_subscription.py` - Generates subscription updates
    - `pyproject.toml` - File that tells pip how to install this module
- `deployment/` - 
    - `create_global_secrets.py` - Creates the secrets.h file during the build process
- `frames/` - Example frame data
- `tools/` - Host tools - DO NOT MODIFY ANYTHING IN THIS DIRECTORY
    - `ectf25/` - Directory with tool source
        - `tv/` - Sends received frames to the decoder
            - `list.py` - Tool to list active decoder subscriptions
            - `subscribe.py` - Tool to update decoder subscriptions
        - `uplink/` - Encodes frames and sends them to satellite
        - `utils/` - Host tool utilities
            - `decoder.py` - Interface with decoder hardware/firmware. This file should not be directly executed.
            - `flash.py` - Firmware update utility
            - `stress_test.py` - Utility for testing decoder
            - `tester.py` - Utility for testing decoder
        - `satellite.py` - Broadcasts frames from uplink to all decoders
    - `pyproject.toml` - File that tells pip how to install this module
