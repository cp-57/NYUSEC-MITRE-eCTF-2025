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
#include "mxc_device.h"
#include "mxc_delay.h"
#include "mxc_sys.h"
#include "aes.h"


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
// int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
//     int result = 0;

//     // Ensure valid length (must be a multiple of AES block size)
//     if (len <= 0 || len % BLOCK_SIZE != 0) {
//         return -1;
//     }

//     // Configure AES decryption request
//     mxc_aes_req_t aes_req;
//     aes_req.length = len / 4;  // Convert byte length to 32-bit word length
//     aes_req.inputData = (uint32_t*)ciphertext;
//     aes_req.resultData = (uint32_t*)plaintext;
//     aes_req.keySize = MXC_AES_256BITS;  // Change to 128 or 192 if needed
//     aes_req.encryption = MXC_AES_DECRYPT_EXT_KEY;

//     // Disable AES peripheral before setting key
//     MXC_AES->ctrl = 0x00;

//     // Set AES key size and load the key into hardware
//     MXC_AES_SetKeySize(MXC_AES_256BITS);  // Update if using AES-128 or AES-192
//     MXC_AES_SetExtKey(key, MXC_AES_256BITS);

//     // Enable AES peripheral
//     MXC_AES->ctrl |= 0x01;

//     // Perform hardware AES decryption
//     result = MXC_AES_Decrypt(&aes_req);
//     if (result != E_SUCCESS) {
//         return result;  // Return error code
//     }

//     return 0;  // Success
// }

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
