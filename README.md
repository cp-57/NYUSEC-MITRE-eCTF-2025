# NYUSEC eCTF 2025 - Satellite TV System

## Brief Overview of Security Features Added + Rationale
- Implemented ChaCha20-Poly1305 encryption for both frames and subscription updates, ensuring confidentiality and authenticity.
- Each encrypted frame (frame_packet_t) and subscription update (encrypted_subscription_update_packet_t) includes an authentication tag (TAG[16]), preventing tampering during transit.
- Subscription state is integrity-protected using MD5 hashes stored in channel_status_t, preventing unauthorized modifications in memory. Subscriptions are only processed if they pass hash verification (verify_subscription_hash()).
- Validate that timestamps always increase (verify_timestamp()), ensuring old messages cannot be replayed
- Side-channel resistance: Introduced random execution delays (rand_delay()) in key security checks (timestamp verification, decryption, subscription validation) to mitigate timing attacks.
- Adusted read_bytes() with modulo operation and proper error reporting to mitigate overflows.

## Layout

- `decoder/` - Firmware for the television decoder.
    - `project.mk` - This file defines project specific variables included in the Makefile
    - `Makefile` - This makefile is invoked by the eCTF tools when creating a decoder.
    - `Dockerfile` - Describes the build environment used by eCTF build tools.
    - `entry.sh` - Entry point for Dockerfile.
    - `inc/` - Directory with c header files
    - `src/` - Directory with c source files
    - `wolfssl/` - wolfSSL crypto library
    - `deployment/` - 
        - `create_global_secrets.py` - Creates the secrets.h file during the build process
- `design/` - Host design elements
    - `ectf25_design/` - Host design source code
        - `encoder.py` - Encodes frames
        - `gen_secrets.py` - Generates shared secrets
        - `gen_subscription.py` - Generates subscription updates
    - `pyproject.toml` - File that tells pip how to install this module
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
