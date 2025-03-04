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

// ChaCha20 constants
static const uint32_t SIGMA[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

// Poly1305 constants
#define P1305_PRIME ((1ULL << 130) - 5)

static uint32_t rotl32(uint32_t x, int n) {
    return (x << n) | (x >> (32 - n));
}

static void chacha20_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl32(*d, 16);
    *c += *d; *b ^= *c; *b = rotl32(*b, 12);
    *a += *b; *d ^= *a; *d = rotl32(*d, 8);
    *c += *d; *b ^= *c; *b = rotl32(*b, 7);
}

static void chacha20_block(uint32_t *state, uint8_t *output) {
    uint32_t x[16];
    memcpy(x, state, sizeof(x));

    for (int i = 0; i < 10; i++) {
        // Column rounds
        chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarter_round(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarter_round(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarter_round(&x[3], &x[7], &x[11], &x[15]);
        // Diagonal rounds
        chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
    }

    for (int i = 0; i < 16; i++) {
        x[i] += state[i];
        ((uint32_t*)output)[i] = x[i];
    }
}

// Poly1305 functions
static void poly1305_blocks(chacha20_poly1305_ctx *ctx, const uint8_t *data, size_t len, int final) {
    uint32_t h0, h1, h2, h3, h4;
    uint32_t r0, r1, r2, r3, r4;
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;
    
    // Initialize accumulator
    h0 = ((uint32_t*)ctx->mac)[0];
    h1 = ((uint32_t*)ctx->mac)[1];
    h2 = ((uint32_t*)ctx->mac)[2];
    h3 = ((uint32_t*)ctx->mac)[3];
    
    // Process r-value from poly key
    r0 = ((uint32_t*)ctx->poly_key)[0] & 0x3ffffff;
    r1 = (((uint32_t*)ctx->poly_key)[0] >> 26 | ((uint32_t*)ctx->poly_key)[1] << 6) & 0x3ffffff;
    r2 = (((uint32_t*)ctx->poly_key)[1] >> 20 | ((uint32_t*)ctx->poly_key)[2] << 12) & 0x3ffffff;
    r3 = (((uint32_t*)ctx->poly_key)[2] >> 14 | ((uint32_t*)ctx->poly_key)[3] << 18) & 0x3ffffff;
    r4 = ((uint32_t*)ctx->poly_key)[3] >> 8 & 0x3ffffff;
    
    while (len >= 16) {
        // Load block
        uint32_t t0 = ((uint32_t*)data)[0];
        uint32_t t1 = ((uint32_t*)data)[1];
        uint32_t t2 = ((uint32_t*)data)[2];
        uint32_t t3 = ((uint32_t*)data)[3];
        
        // Add to accumulator
        h0 += t0 & 0x3ffffff;
        h1 += ((t0 >> 26) | (t1 << 6)) & 0x3ffffff;
        h2 += ((t1 >> 20) | (t2 << 12)) & 0x3ffffff;
        h3 += ((t2 >> 14) | (t3 << 18)) & 0x3ffffff;
        h4 += (t3 >> 8) | (1 << 24);
        
        // Multiply accumulator by r
        d0 = ((uint64_t)h0 * r0) + ((uint64_t)h1 * (5 * r4)) + ((uint64_t)h2 * (5 * r3)) + ((uint64_t)h3 * (5 * r2)) + ((uint64_t)h4 * (5 * r1));
        d1 = ((uint64_t)h0 * r1) + ((uint64_t)h1 * r0) + ((uint64_t)h2 * (5 * r4)) + ((uint64_t)h3 * (5 * r3)) + ((uint64_t)h4 * (5 * r2));
        d2 = ((uint64_t)h0 * r2) + ((uint64_t)h1 * r1) + ((uint64_t)h2 * r0) + ((uint64_t)h3 * (5 * r4)) + ((uint64_t)h4 * (5 * r3));
        d3 = ((uint64_t)h0 * r3) + ((uint64_t)h1 * r2) + ((uint64_t)h2 * r1) + ((uint64_t)h3 * r0) + ((uint64_t)h4 * (5 * r4));
        d4 = ((uint64_t)h0 * r4) + ((uint64_t)h1 * r3) + ((uint64_t)h2 * r2) + ((uint64_t)h3 * r1) + ((uint64_t)h4 * r0);
        
        // Partial reduction mod 2^130 - 5
        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & 0x3ffffff;
        d1 += c;     c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & 0x3ffffff;
        d2 += c;     c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & 0x3ffffff;
        d3 += c;     c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & 0x3ffffff;
        d4 += c;     c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & 0x3ffffff;
        h0 += c * 5; c = h0 >> 26; h0 = h0 & 0x3ffffff;
        h1 += c;
        
        data += 16;
        len -= 16;
    }
    
    // Store accumulator back
    ((uint32_t*)ctx->mac)[0] = h0;
    ((uint32_t*)ctx->mac)[1] = h1;
    ((uint32_t*)ctx->mac)[2] = h2;
    ((uint32_t*)ctx->mac)[3] = h3;
}

void chacha20_poly1305_init(chacha20_poly1305_ctx *ctx, const uint8_t *key, const uint8_t *nonce) {
    // Initialize ChaCha20 state
    memcpy(&ctx->state[0], SIGMA, 16);
    memcpy(&ctx->state[4], key, 32);
    ctx->state[12] = 0;  // Counter
    memcpy(&ctx->state[13], nonce, 12);
    
    // Generate Poly1305 key
    uint8_t poly_key[64];
    chacha20_block(ctx->state, poly_key);
    memcpy(ctx->poly_key, poly_key, 32);
    
    // Initialize MAC
    memset(ctx->mac, 0, 16);
    
    ctx->position = 64;  // Force new block generation
    ctx->aad_len = 0;
    ctx->data_len = 0;
}

void chacha20_poly1305_aad(chacha20_poly1305_ctx *ctx, const uint8_t *aad, size_t aad_len) {
    if (aad_len > 0) {
        poly1305_blocks(ctx, aad, aad_len, 0);
        ctx->aad_len += aad_len;
    }
}

void chacha20_poly1305_encrypt(chacha20_poly1305_ctx *ctx, const uint8_t *plaintext,
                             uint8_t *ciphertext, size_t length, uint8_t *tag) {
    // Encrypt data
    for (size_t i = 0; i < length; i++) {
        if (ctx->position == 64) {
            chacha20_block(ctx->state, ctx->buffer);
            ctx->position = 0;
            ctx->state[12]++;
        }
        ciphertext[i] = plaintext[i] ^ ctx->buffer[ctx->position++];
    }
    
    // Update MAC with ciphertext
    poly1305_blocks(ctx, ciphertext, length, 0);
    ctx->data_len += length;
    
    // Finalize MAC with lengths
    uint8_t final_block[16];
    ((uint64_t*)final_block)[0] = ctx->aad_len;
    ((uint64_t*)final_block)[1] = ctx->data_len;
    poly1305_blocks(ctx, final_block, 16, 1);
    
    // Copy MAC to tag
    memcpy(tag, ctx->mac, 16);
}

int chacha20_poly1305_decrypt(chacha20_poly1305_ctx *ctx, const uint8_t *ciphertext,
                            uint8_t *plaintext, size_t length, const uint8_t *tag) {
    uint8_t calculated_tag[16];
    chacha20_poly1305_ctx verify_ctx = *ctx;
    
    // Update MAC with ciphertext
    poly1305_blocks(&verify_ctx, ciphertext, length, 0);
    verify_ctx.data_len += length;
    
    // Finalize MAC with lengths
    uint8_t final_block[16];
    ((uint64_t*)final_block)[0] = verify_ctx.aad_len;
    ((uint64_t*)final_block)[1] = verify_ctx.data_len;
    poly1305_blocks(&verify_ctx, final_block, 16, 1);
    
    // Get calculated tag
    memcpy(calculated_tag, verify_ctx.mac, 16);
    
    // Constant-time comparison of tags
    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= calculated_tag[i] ^ tag[i];
    }
    
    if (diff != 0) {
        return -1;  // Authentication failed
    }
    
    // Decrypt data
    for (size_t i = 0; i < length; i++) {
        if (ctx->position == 64) {
            chacha20_block(ctx->state, ctx->buffer);
            ctx->position = 0;
            ctx->state[12]++;
        }
        plaintext[i] = ciphertext[i] ^ ctx->buffer[ctx->position++];
    }
    
    return 0;  // Success
}

/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error


    // Encrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesEncryptDirect(&ctx, ciphertext + i, plaintext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result = wc_AesDecryptDirect(&ctx, plaintext + i, ciphertext + i);
        if (result != 0)
            return result; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}

#endif
