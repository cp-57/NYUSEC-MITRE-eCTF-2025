/**
 * @file "simple_crypto.h"
 * @author Ben Janis
 * @brief Simplified Crypto API Header 
 * @date 2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE
#ifndef ECTF_CRYPTO_H
#define ECTF_CRYPTO_H

#include "wolfssl/wolfcrypt/chacha20_poly1305.h"
#include "wolfssl/wolfcrypt/hash.h"

/******************************** MACRO DEFINITIONS ********************************/
#define KEY_SIZE 32

/******************************** FUNCTION PROTOTYPES ********************************/

// int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);
int decrypt_sym(uint8_t *polyKey, uint8_t *polyIV, uint8_t *inAAD, uint32_t inAADlen, uint8_t *ciphertext, 
                uint32_t cipher_len, uint8_t *authTag, uint8_t *plaintext);


#endif // CRYPTO_EXAMPLE
#endif // ECTF_CRYPTO_H
