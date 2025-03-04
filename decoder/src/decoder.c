/**
 * @file    decoder.c
 * @author  Samuel Meyers
 * @brief   eCTF Decoder Example Design Implementation
 * @date    2025
 *
 * This source file is part of an example system for MITRE's 2025 Embedded System CTF (eCTF).
 * This code is being provided only for educational purposes for the 2025 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "status_led.h"
#include "board.h"
#include "mxc_delay.h"
#include "simple_flash.h"
#include "host_messaging.h"
#include "secrets.h"
#include "wolfssl/wolfcrypt/hmac.h"
#include "simple_crypto.h"

#include "simple_uart.h"


/**********************************************************
 ******************* PRIMITIVE TYPES **********************
 **********************************************************/

#define timestamp_t uint64_t
#define channel_id_t uint32_t
#define decoder_id_t uint32_t
#define pkt_len_t uint16_t

/**********************************************************
 *********************** CONSTANTS ************************
 **********************************************************/

#define MAX_CHANNEL_COUNT 8
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))


/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html
typedef struct {
    channel_id_t channel;
    timestamp_t timestamp;
    uint8_t hmac[16];    
    uint8_t data[FRAME_SIZE];
} frame_packet_t;

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
} channel_status_t;

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;


/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

/** @brief Checks whether the decoder is subscribed to a given channel
 *
 *  @param channel The channel number to be checked.
 *  @return 1 if the the decoder is subscribed to the channel.  0 if not.
*/
int is_subscribed(channel_id_t channel, timestamp_t timestamp) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) { 
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active && timestamp >= decoder_status.subscribed_channels[i].start_timestamp && timestamp <= decoder_status.subscribed_channels[i].end_timestamp) {
            return 1;
        }
    }
    return 0;
}


/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/** @brief Lists out the actively subscribed channels over UART.
 *
 *  @return 0 if successful.
*/
int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            resp.channel_info[resp.n_channels].channel =  decoder_status.subscribed_channels[i].id;
            resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
            resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
            resp.n_channels++;
        }
    }

    len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);

    // Success message
    write_packet(LIST_MSG, &resp, len);
    return 0;
}


/** @brief Updates the channel subscription for a subset of channels.
 *
 *  @param pkt_len The length of the incoming packet
 *  @param update A pointer to an array of channel_update structs,
 *      which contains the channel number, start, and end timestamps
 *      for each channel being updated.
 *
 *  @note Take care to note that this system is little endian.
 *
 *  @return 0 upon success.  -1 if error.
*/
int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
    int i;

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

    // Find the first empty slot in the subscription array
    for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
            if (update->start_timestamp > update->end_timestamp) {
                STATUS_LED_RED();
                print_error("Failed to update subscription - end time is before start time. Please ensure your time is linearly increasing.\n");
                return -1;
            }
            decoder_status.subscribed_channels[i].active = true;
            decoder_status.subscribed_channels[i].id = update->channel;
            decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
            decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
            break;
        }
    }

    // If we do not have any room for more subscriptions
    if (i == MAX_CHANNEL_COUNT) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - max subscriptions installed\n");
        return -1;
    }

    flash_simple_erase_page(FLASH_STATUS_ADDR);
    flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    // Success message with an empty body
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

// Add functions to aid in decoding
uint8_t* get_channel_key(channel_id_t channel) {
    switch (channel) {
        case 0: return (uint8_t*)CHANNEL_0_KEY;
        case 1: return (uint8_t*)CHANNEL_1_KEY;
        case 3: return (uint8_t*)CHANNEL_3_KEY;
        case 4: return (uint8_t*)CHANNEL_4_KEY;
        default: return (uint8_t*)AES_KEY;
    }
}

// Function to get channel-specific HMAC key
uint8_t* get_hmac_key(channel_id_t channel) {
    switch (channel) {
        case 0: return (uint8_t*)CHANNEL_0_HMAC;
        case 1: return (uint8_t*)CHANNEL_1_HMAC;
        case 3: return (uint8_t*)CHANNEL_3_HMAC;
        case 4: return (uint8_t*)CHANNEL_4_HMAC;
        default: return (uint8_t*)DEFAULT_HMAC;
    }
}

// Constant-time comparison
int secure_compare(const uint8_t *a, const uint8_t *b, size_t length) {
    int result = 0;
    for (size_t i = 0; i < length; i++) {
        result |= a[i] ^ b[i];
    }
    return result == 0 ? 1 : 0;
}

int remove_pkcs7_padding(uint8_t *plaintext, size_t *len) {
    if (*len == 0) return -1;
    uint8_t pad_value = plaintext[*len - 1];  
    if (pad_value > 16 || pad_value == 0) return -1;  

    for (int i = 0; i < pad_value; i++) {
        if (plaintext[*len - 1 - i] != pad_value) return -1;
    }

    *len -= pad_value;
    return 0;
}

int validate_hmac(frame_packet_t *frame, uint8_t *hmac_key) {
    Hmac hmac;  
    uint8_t calculated_hmac[16];
    char debug_buffer[256]; // Buffer for formatting debug messages

    print_debug("===== HMAC VALIDATION DEBUGGING =====");
    
    sprintf(debug_buffer, "Frame channel ID: %u", frame->channel);
    print_debug(debug_buffer);
    
    sprintf(debug_buffer, "Frame timestamp: %llu", frame->timestamp);
    print_debug(debug_buffer);
    
    print_debug("Received HMAC in frame:");
    print_hex_debug(frame->hmac, 16);
    
    print_debug("Using HMAC key for verification:");
    print_hex_debug(hmac_key, 32);
    
    wc_HmacInit(&hmac, NULL, INVALID_DEVID);
    
    uint8_t hmac_data[sizeof(channel_id_t) + sizeof(timestamp_t) + FRAME_SIZE];
    uint32_t offset = 0;
    
    // Print sizes to verify correct memory layout
    sprintf(debug_buffer, "Size of channel_id_t: %lu bytes", sizeof(channel_id_t));
    print_debug(debug_buffer);
    
    sprintf(debug_buffer, "Size of timestamp_t: %lu bytes", sizeof(timestamp_t));
    print_debug(debug_buffer);
    
    sprintf(debug_buffer, "Size of FRAME_SIZE: %d bytes", FRAME_SIZE);
    print_debug(debug_buffer);
    
    sprintf(debug_buffer, "Total HMAC input size: %lu bytes", sizeof(hmac_data));
    print_debug(debug_buffer);
    
    memcpy(hmac_data + offset, &frame->channel, sizeof(channel_id_t));
    sprintf(debug_buffer, "Channel bytes added at offset %u:", offset);
    print_debug(debug_buffer);
    print_hex_debug(hmac_data + offset, sizeof(channel_id_t));
    offset += sizeof(channel_id_t);
    
    memcpy(hmac_data + offset, &frame->timestamp, sizeof(timestamp_t));
    sprintf(debug_buffer, "Timestamp bytes added at offset %u:", offset);
    print_debug(debug_buffer);
    print_hex_debug(hmac_data + offset, sizeof(timestamp_t));
    offset += sizeof(timestamp_t);
    
    memcpy(hmac_data + offset, frame->data, FRAME_SIZE);
    sprintf(debug_buffer, "First 16 bytes of encrypted data at offset %u:", offset);
    print_debug(debug_buffer);
    print_hex_debug(frame->data, 16);
    print_debug("Last 16 bytes of encrypted data:");
    print_hex_debug(frame->data + FRAME_SIZE - 16, 16);
    
    print_debug("Checking endianness of timestamp bytes:");
    for(int i = 0; i < sizeof(timestamp_t); i++) {
        sprintf(debug_buffer, "Byte %d: 0x%02x", i, *(((uint8_t*)&frame->timestamp) + i));
        print_debug(debug_buffer);
    }
    
    wc_HmacSetKey(&hmac, WC_SHA256, hmac_key, 32); 
    wc_HmacUpdate(&hmac, hmac_data, sizeof(hmac_data));
    wc_HmacFinal(&hmac, calculated_hmac);

    print_debug("Complete C HMAC Input Data:");
    print_hex_debug(hmac_data, sizeof(hmac_data));

    print_debug("Calculated HMAC (16 bytes):");
    print_hex_debug(calculated_hmac, 16);
    
    
    wc_HmacFree(&hmac);
    
    print_debug("===== END HMAC VALIDATION DEBUGGING =====");
    
    return 1; 
}

/** @brief Processes a packet containing frame data.
 *
 *  @param pkt_len A pointer to the incoming packet.
 *  @param new_frame A pointer to the incoming packet.
 *
 *  @return 0 if successful.  -1 if data is from unsubscribed channel.
*/
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[128] = {0};
    uint16_t frame_size;
    channel_id_t channel;
    timestamp_t timestamp = new_frame->timestamp;

    // Frame size is the size of the packet minus the size of non-frame elements
    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + sizeof(new_frame->hmac));
    channel = new_frame->channel;

    // Get the correct keys for the channel
    uint8_t *decryption_key = get_channel_key(channel);
    uint8_t *hmac_key = get_hmac_key(channel);

    // Print received HMAC for debugging
    print_debug("Received HMAC:");
    print_hex_debug(new_frame->hmac, 16);

    if (!validate_hmac(new_frame, hmac_key)) {
        STATUS_LED_RED();
        // print_error("HMAC verification failed - message may be tampered with\n");
        // Verify HMAC - temporarily bypassed for testing
        // return -1;
    }

    // GCM – wc_AesGcmSetKey, wc_AesGcmEncrypt, wc_AesGcmDecrypt
    // CTR - 

    // Check subscription
    if (is_subscribed(channel, timestamp)) {
        print_debug("Subscription Valid\n");
        
        // Debug print to verify the decryption key
        print_debug("Using AES Key for Channel:");
        printf("%u\n", channel);
        print_hex_debug(decryption_key, 16);
        
        // Buffer for decrypted output
        uint8_t decrypted[frame_size];
        
        // Decrypt the frame
        int decrypt_status = decrypt_sym(new_frame->data, frame_size, decryption_key, decrypted);
        if (decrypt_status != 0) {
            print_error("Decryption failed\n");
            return -1;
        }

        // Remove padding
        size_t new_len = frame_size;
        if (remove_pkcs7_padding(decrypted, &new_len) != 0) {
            print_error("Invalid padding detected after decryption\n");
            return -1;
        }

        // Debug output for decrypted data
        print_debug("Decrypted Frame:");
        print_hex_debug(decrypted, new_len);

        // Send decrypted data back
        write_packet(DECODE_MSG, decrypted, new_len);
        return 0;
    } else {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data OR timestamp invalid... %u\n", channel);
        print_error(output_buf);
        return -1;
    }
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    int ret;

    // Initialize the flash peripheral to enable access to persistent memory
    flash_simple_init();

    // Read starting flash values into our flash status struct
    flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
        /* If this is the first boot of this decoder, mark all channels as unsubscribed.
        *  This data will be persistent across reboots of the decoder. Whenever the decoder
        *  processes a subscription update, this data will be updated.
        */
        print_debug("First boot.  Setting flash...\n");

        decoder_status.first_boot = FLASH_FIRST_BOOT;

        channel_status_t subscription[MAX_CHANNEL_COUNT];

        for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
            subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
            subscription[i].active = false;
        }

        // Write the starting channel subscriptions into flash.
        memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT*sizeof(channel_status_t));

        flash_simple_erase_page(FLASH_STATUS_ADDR);
        flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
    }

    // Initialize the uart peripheral to enable serial I/O
    ret = uart_init();
    if (ret < 0) {
        STATUS_LED_ERROR();
        // if uart fails to initialize, do not continue to execute
        while (1);
    }
}

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the projectk.mk file. */
#ifdef CRYPTO_EXAMPLE
void crypto_example(void) {
    // Example of how to utilize included simple_crypto.h

    // This string is 16 bytes long including null terminator
    // This is the block size of included symmetric encryption
    char *data = "Crypto Example!";
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t key[KEY_SIZE];
    uint8_t hash_out[HASH_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    char output_buf[128] = {0};

    // Zero out the key
    bzero(key, BLOCK_SIZE);

    // Encrypt example data and print out
    encrypt_sym((uint8_t*)data, BLOCK_SIZE, key, ciphertext);
    print_debug("Encrypted data: \n");
    print_hex_debug(ciphertext, BLOCK_SIZE);

    // Hash example encryption results
    hash(ciphertext, BLOCK_SIZE, hash_out);

    // Output hash result
    print_debug("Hash result: \n");
    print_hex_debug(hash_out, HASH_SIZE);

    // Decrypt the encrypted message and print out
    decrypt_sym(ciphertext, BLOCK_SIZE, key, decrypted);
    sprintf(output_buf, "Decrypted message: %s\n", decrypted);
    print_debug(output_buf);
}
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    uint8_t uart_buf[100];
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    print_debug("Decoder Booted!\n");

    // process commands forever
    while (1) {
        print_debug("Ready\n");

        STATUS_LED_GREEN();

        result = read_packet(&cmd, uart_buf, &pkt_len);

        if (result < 0) {
            STATUS_LED_ERROR();
            print_error("Failed to receive cmd from host\n");
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:
            STATUS_LED_CYAN();

            #ifdef CRYPTO_EXAMPLE
                // Run the crypto example
                // TODO: Remove this from your design
                crypto_example();
            #endif // CRYPTO_EXAMPLE

            // Print the boot flag
            // TODO: Remove this from your design
            list_channels();
            break;

        // Handle decode command
        case DECODE_MSG:
            STATUS_LED_PURPLE();
            decode(pkt_len, (frame_packet_t *)uart_buf);
            break;

        // Handle subscribe command
        case SUBSCRIBE_MSG:
            STATUS_LED_YELLOW();
            update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}