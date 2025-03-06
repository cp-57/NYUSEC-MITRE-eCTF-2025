/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include <stdint.h>
#include <string.h>

int decrypt_sym(uint8_t *polyKey, uint8_t *polyIV, uint8_t *inAAD, uint32_t inAADlen, uint8_t *ciphertext, 
                uint32_t cipher_len, uint8_t *authTag, uint8_t *plaintext) {

    int ret = wc_ChaCha20Poly1305_Decrypt(polyKey, polyIV, inAAD, inAADlen,
                                         ciphertext, cipher_len, authTag, plaintext);

    return ret;
}

#endif
