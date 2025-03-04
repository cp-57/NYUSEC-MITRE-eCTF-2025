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

#include "wolfssl/wolfcrypt/aes.h"
#include "wolfssl/wolfcrypt/hash.h"
#include <stdint.h>
#include <string.h>

/******************************** MACRO DEFINITIONS ********************************/
#define BLOCK_SIZE AES_BLOCK_SIZE
#define KEY_SIZE 16
#define HASH_SIZE MD5_DIGEST_SIZE

#define CHACHA20_KEY_SIZE 32
#define CHACHA20_NONCE_SIZE 16
#define CHACHA20_BLOCK_SIZE 64
#define POLY1305_TAG_SIZE 16

/******************************** TYPE DEFINITIONS ********************************/
typedef struct {
    uint32_t state[16];  // ChaCha20 state
    uint8_t buffer[64];  // Working buffer
    size_t position;     // Current position in buffer
    uint8_t poly_key[32];  // Poly1305 key
    uint8_t mac[16];     // MAC accumulator
    uint64_t aad_len;    // Length of additional authenticated data
    uint64_t data_len;   // Length of encrypted/decrypted data
} chacha20_poly1305_ctx;

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
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext);

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *           ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *           BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *           the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *           plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext);

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *           to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *           hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out);

typedef struct {
    uint32_t state[16];
    uint8_t buffer[64];
    size_t position;
} chacha20_ctx;

// Function declarations
void chacha20_init(chacha20_ctx *ctx, const uint8_t *key, const uint8_t *nonce);
void chacha20_decrypt(chacha20_ctx *ctx, const uint8_t *ciphertext, uint8_t *plaintext, size_t length);
void chacha20_encrypt(chacha20_ctx *ctx, const uint8_t *plaintext, uint8_t *ciphertext, size_t length);

/** @brief Initialize ChaCha20-Poly1305 context
 *
 * @param ctx The context to initialize
 * @param key 32-byte key
 * @param nonce 16-byte nonce
 */
void chacha20_poly1305_init(chacha20_poly1305_ctx *ctx, const uint8_t *key, const uint8_t *nonce);

/** @brief Add additional authenticated data
 *
 * @param ctx The context
 * @param aad The additional data to authenticate
 * @param aad_len Length of the additional data
 */
void chacha20_poly1305_aad(chacha20_poly1305_ctx *ctx, const uint8_t *aad, size_t aad_len);

/** @brief Encrypt data and compute authentication tag
 *
 * @param ctx The context
 * @param plaintext Input plaintext
 * @param ciphertext Output ciphertext
 * @param length Length of data
 * @param tag Output authentication tag (16 bytes)
 */
void chacha20_poly1305_encrypt(chacha20_poly1305_ctx *ctx, const uint8_t *plaintext, 
                             uint8_t *ciphertext, size_t length, uint8_t *tag);

/** @brief Decrypt data and verify authentication tag
 *
 * @param ctx The context
 * @param ciphertext Input ciphertext
 * @param plaintext Output plaintext
 * @param length Length of data
 * @param tag Input authentication tag (16 bytes)
 * @return 0 if tag is valid, -1 if invalid
 */
int chacha20_poly1305_decrypt(chacha20_poly1305_ctx *ctx, const uint8_t *ciphertext,
                            uint8_t *plaintext, size_t length, const uint8_t *tag);

#endif // CRYPTO_EXAMPLE
#endif // ECTF_CRYPTO_H
