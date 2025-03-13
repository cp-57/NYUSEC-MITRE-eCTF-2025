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

#include "simple_uart.h"
#include "simple_crypto.h"
#include "secrets.h"
#include "random_w.h"

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

/* 
 * MAX_UART_BUFFER_SIZE is the maximum size of any single incoming message
 * that can be processed properly. Messages larger than this will return an error.
 */
#define MAX_UART_BUFFER_SIZE 256
#define EMERGENCY_CHANNEL 0
#define FRAME_SIZE 64
#define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
// This is a canary value so we can confirm whether this decoder has booted before
#define FLASH_FIRST_BOOT 0xDEADBEEF
#define MD5_HASH_SIZE 16

/**********************************************************
 ********************* STATE MACROS ***********************
 **********************************************************/

// Calculate the flash address where we will store channel info as the 2nd to last page available
#define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))

#define OUTPUT_BUF_SIZE 128

/**********************************************************
 *********** COMMUNICATION PACKET DEFINITIONS *************
 **********************************************************/

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
// for more information on what struct padding does, see:
// https://www.gnu.org/software/c-intro-and-ref/manual/html_node/Structure-Layout.html

/**
 * @brief Structure to store frame data with authentication and encryption fields
 * 
 * This packet format includes:
 * - channel ID: identifies which channel this frame belongs to
 * - timestamp: time value of packet
 * - nonce: unique value for each encryption to prevent reuse
 * - tag: authentication tag to verify message integrity
 * - ciphertext: the encrypted payload limited to FRAME_SIZE bytes
 */

typedef struct {
    channel_id_t channel; 
    uint64_t timestamp; 
    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t ciphertext[64]; 
} frame_packet_t;

/**
 * @brief Plaintext subscription update information
 *
 * Contains the parameters needed to update a channel subscription:
 * - decoder_id: Identifies which decoder this subscription is for
 * - start_timestamp: Beginning of subscription validity period
 * - end_timestamp: End of subscription validity period
 * - channel: The channel ID being subscribed to
 */

typedef struct {
    decoder_id_t decoder_id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    channel_id_t channel;
} subscription_update_packet_t;


/**
 * @brief Encrypted container for subscription updates
 *
 * This structure protects subscription updates for secure transmission:
 * - nonce: 12-byte unique value used during encryption
 * - tag: 16-byte authentication tag to verify message integrity
 * - ciphertext: The encrypted subscription_update_packet_t
 *
 */

typedef struct {
    uint8_t nonce[12];
    uint8_t tag[16];
    uint8_t ciphertext[sizeof(subscription_update_packet_t)];
} encrypted_subscription_update_packet_t;


/**
 * @brief Channel subscription information for reporting
 *
 * Used when listing active subscriptions, containing:
 * - channel: The channel identifier
 * - start: Beginning of subscription validity period
 * - end: End of subscription validity period
 */

typedef struct {
    channel_id_t channel;
    timestamp_t start;
    timestamp_t end;
} channel_info_t;

/**
 * @brief Response packet for listing active channel subscriptions
 *
 * Contains:
 * - n_channels: Number of active subscriptions in the response
 * - channel_info: Array of subscription details for each active channel
 *   (only the first n_channels entries are valid)
 */

typedef struct {
    uint32_t n_channels;
    channel_info_t channel_info[MAX_CHANNEL_COUNT];
} list_response_t;

#pragma pack(pop) // Tells the compiler to resume padding struct members

/**********************************************************
 ******************** TYPE DEFINITIONS ********************
 **********************************************************/

/**
 * @brief Internal representation of a channel subscription with integrity protection
 *
 * This structure maintains subscription state with tamper protection:
 * - active: Whether this subscription slot is in use
 * - id: The channel identifier
 * - start_timestamp: Beginning of subscription validity period
 * - end_timestamp: End of subscription validity period
 * - hash: MD5 hash of the above fields to detect memory tampering
 */
typedef struct {
    bool active;
    channel_id_t id;
    timestamp_t start_timestamp;
    timestamp_t end_timestamp;
    uint8_t hash[MD5_HASH_SIZE];
} channel_status_t;

/**
 * @brief Persistent storage structure saved to flash memory
 *
 * Contains:
 * - first_boot: Canary value (FLASH_FIRST_BOOT) to detect initial boot
 * - subscribed_channels: Array of all channel subscriptions
 *
 * This structure is persisted to flash to maintain subscriptions
 * across power cycles and resets
 */

typedef struct {
    uint32_t first_boot; // if set to FLASH_FIRST_BOOT, device has booted before.
    channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
} flash_entry_t;

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

// This is used to track decoder subscriptions
flash_entry_t decoder_status;

timestamp_t prev_time;

/**********************************************************
 ******************* UTILITY FUNCTIONS ********************
 **********************************************************/

 /**
 * @brief Calculate a cryptographic hash of subscription data to detect tampering
 * 
 * This function generates a hash derived from subscription fields:
 * 1. Creates a temporary structure containing only the essential fields
 *    (active status, channel ID, start and end timestamps)
 * 2. Excludes the hash field itself to prevent circular dependencies
 * 3. Generates an MD5 hash of the subscription data
 * 4. Stores the resulting hash for later verification
 * 
 * @param subscription Pointer to the subscription data to hash
 * @param hash_out Pointer to a buffer where the calculated hash will be stored
 * 
 * @return 0 on success, non-zero on hash calculation failure
 */
int calculate_subscription_hash(channel_status_t *subscription, uint8_t *hash_out) {
    struct {
        bool active;
        channel_id_t id;
        timestamp_t start_timestamp;
        timestamp_t end_timestamp;
    } hash_data = {0};

    hash_data.active = subscription->active;
    hash_data.id = subscription->id;
    hash_data.start_timestamp = subscription->start_timestamp;
    hash_data.end_timestamp = subscription->end_timestamp;

    int result = hash(&hash_data, sizeof(hash_data), hash_out);
    
    return result;
}

/**
 * @brief Verify the integrity of a subscription by checking its cryptographic hash
 * 
 * This function validates that a subscription hasn't been tampered with:
 * 1. Recalculates the expected hash from the current subscription data
 * 2. Compares the calculated hash with the stored hash
 * 3. Logs an error message if verification fails
 * 
 * @param subscription Pointer to the subscription data to verify
 * 
 * @return 1 if verification succeeds, 0 if it fails
 */
int verify_subscription_hash(channel_status_t *subscription) {
    rand_delay();
    uint8_t calculated_hash[MD5_HASH_SIZE];
    
    if (calculate_subscription_hash(subscription, calculated_hash) != 0) {
        print_error("Hash calculation failed\n");
        return 0; 
    }
    
    int result = (memcmp(calculated_hash, subscription->hash, MD5_HASH_SIZE) == 0);
    
    if (!result) {
        print_error("Hash verification FAILED\n");
    }
    
    return result;
}

/**
 * @brief Security check for channel subscription validity
 * 
 * Verifies that:
 * 1. The channel is either an emergency broadcast or subscribed
 * 2. The current time is within the subscription window
 * 3. The subscription hash is valid (to detect tampering)
 * 
 * @param channel The channel ID to check
 * @param timestamp Current timestamp to validate against subscription window
 * @return 1 if subscription is valid, 0 otherwise
 */
int is_subscribed(channel_id_t channel, timestamp_t timestamp) {
    // Check if this is an emergency broadcast message
    if (channel == EMERGENCY_CHANNEL) {
        return 1;
    }
    // Check if the decoder has has a subscription
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) { 
        if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active && timestamp >= decoder_status.subscribed_channels[i].start_timestamp && timestamp <= decoder_status.subscribed_channels[i].end_timestamp) {
            
            // Verify sub hash
            if (!verify_subscription_hash(&decoder_status.subscribed_channels[i])) {
                print_error("Subscription hash verification failed\n");
                STATUS_LED_RED();
                return 0;
            }
            return 1;
        }
    }
    rand_delay();
    return 0;
}

/** @brief Retrieves the encryption key for a given channel.
 *
 *  This function searches the `CHANNEL_KEYS` array to find the 
 *  corresponding encryption key for the specified channel.
 *
 *  @param channel The channel ID for which the key is being requested.
 *  @return A pointer to the encryption key if found, otherwise NULL.
 */

uint8_t* get_channel_key(channel_id_t channel) {
    for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (CHANNEL_KEYS[i].channel == channel) {
            return (uint8_t*)CHANNEL_KEYS[i].key;
        }
    }
    return NULL; 
}

/**
 * @brief Verify if a timestamp is valid and newer than the monotonic counter
 * 
 * This function checks if the incoming timestamp is greater than our current counter
 * to prevent replay attacks and ensure forward progression of time.
 * 
 * @param timestamp The timestamp from the incoming frame to validate
 * @return 1 if timestamp is authentic and newer than current time, 0 otherwise
 */
int verify_timestamp(timestamp_t timestamp) {
    // Check timestamp sequence (increment only forward) 
    if (timestamp > prev_time) {
        return 1;
    }
    return 0;
}

/**
 * @brief Update the counter with a new validated timestamp
 * 
 * After verifying a timestamp is valid, this function updates internal
 * counters to reflect the most recent time.
 * 
 * @param timestamp The new timestamp value to update
 * @return 1 if update succeeded
 */
int update_counter(timestamp_t timestamp) {     
    prev_time = timestamp;
    return 1;
}


/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/

/**
 * @brief List all active channel subscriptions with their validity periods
 * 
 * This function generates a response containing all active channel subscriptions:
 * 1. Initializes an empty response structure
 * 2. Iterates through all subscription slots in memory
 * 3. For each active subscription:
 *    - Verifies the subscription hash to detect tampering
 *    - Adds valid subscriptions to the response packet
 *    - Skips subscriptions with failed hash verification
 * 4. Calculates the total response length based on active subscriptions
 * 5. Transmits the response packet to the host
 * @return 0 on successful operation, regardless of subscription count
 */
int list_channels() {
    list_response_t resp;
    pkt_len_t len;

    resp.n_channels = 0;

    for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
        if (decoder_status.subscribed_channels[i].active) {
            if (!verify_subscription_hash(&decoder_status.subscribed_channels[i])) {
                print_error("Hash verification failed for channel, skipping\n");
                continue;
            }
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


/**
 * @brief Update channel subscription data based on encrypted subscription update
 * 
 * The update_subscription function manages subscription updates:
 * 1. Decrypts the subscription update using the loaded key
 * 2. Validates the update against these policies:
 *    - Prevents subscribing to the emergency channel (reserved)
 *    - Ensures start time is before end time
 * 3. Finds an existing subscription to update or an empty slot
 * 4. Updates the subscription with new channel ID and time bounds
 * 5. Calculates a cryptographic hash of the subscription data
 * 6. Persists the updated subscription to flash storage
 * 
 * @param pkt_len The length of the incoming encrypted packet
 * @param encrypted_update Pointer to the encrypted subscription data
 * 
 * @return 0 on successful subscription update, -1 on any error
 */
int update_subscription(pkt_len_t pkt_len, encrypted_subscription_update_packet_t *encrypted_update) {
    int i;

    const uint8_t *decryption_key = CHACHA_KEY;
    uint16_t subscription_update_size=24;
    
    uint8_t decrypted[subscription_update_size];


    int decrypt_status = decrypt_sym(decryption_key, encrypted_update->nonce, NULL, 0, encrypted_update->ciphertext,
            subscription_update_size, encrypted_update->tag, decrypted);


    if (decrypt_status != 0) {
        STATUS_LED_RED();
        print_error("Subscription failure...\n");
        return -1;
    }

    // transfer decoded subscription update data into the sub update struct
    subscription_update_packet_t *update = (subscription_update_packet_t *)decrypted;

    if (update->channel == EMERGENCY_CHANNEL) {
        STATUS_LED_RED();
        print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
        return -1;
    }

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

            if (calculate_subscription_hash(&decoder_status.subscribed_channels[i], 
                                           decoder_status.subscribed_channels[i].hash) != 0) {
                STATUS_LED_RED();
                print_error("Failed to calculate subscription hash\n");
                return -1;
            }

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
    write_packet(SUBSCRIBE_MSG, NULL, 0);
    return 0;
}

/**
 * @brief Process and decrypt an encrypted frame packet
 * 
 * The decode function performs several operations:
 * 1. Validates the frame size is within acceptable bounds
 * 2. Verifies the timestamp is newer than our current time
 * 3. Checks if the decoder has a valid subscription for the requested channel
 * 4. Retrieves the appropriate decryption key for the channel
 * 5. Creates authentication data (AAD) from channel and timestamp
 * 6. Attempts to decrypt and authenticate the frame
 * 7. Updates the system timestamp if successful
 * 
 * @param pkt_len The length of the incoming packet
 * @param new_frame Pointer to the encrypted frame data structure
 * 
 * @return 0 on successful decryption and processing, -1 on any error
 */
int decode(pkt_len_t pkt_len, frame_packet_t *new_frame) {
    char output_buf[OUTPUT_BUF_SIZE] = {0};
    uint16_t frame_size;
    channel_id_t channel;


    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + sizeof(new_frame->nonce)
         + sizeof(new_frame->tag));
    channel = new_frame->channel;

    rand_delay();

    // Frame bounds checking
    if (frame_size > FRAME_SIZE || frame_size <= 0) {
        STATUS_LED_RED();
        print_error("Invalid frame size detected\n");
        return -1;
    }

    timestamp_t timestamp = new_frame->timestamp;

    rand_delay();

    // Verify timestamp
    if (!verify_timestamp(timestamp)) {
        STATUS_LED_RED();
        snprintf(
            output_buf, sizeof(output_buf),
            "Timestamp out of order.  %llu\n", timestamp);
        print_error(output_buf);
        return -1; 
    }

    uint8_t aad[12]; 
    memcpy(aad, &channel, sizeof(channel));
    memcpy(aad + sizeof(channel), &timestamp, sizeof(timestamp));

    rand_delay();

    if (!is_subscribed(channel, timestamp)) {
        STATUS_LED_RED();
        snprintf(
            output_buf, sizeof(output_buf),
            "Receiving unsubscribed channel data or timestamp invalid.  %lu\n", channel);
        print_error(output_buf);
        return -1;
    }

    const uint8_t *decryption_key = get_channel_key(channel);

    // Buffer for decrypted output
    uint8_t decrypted[frame_size];

    rand_delay();

    int decrypt_status = decrypt_sym(decryption_key, new_frame->nonce, aad, 12, new_frame->ciphertext,
            frame_size, new_frame->tag, decrypted);


    rand_delay();

    if (decrypt_status == 0) {
        write_packet(DECODE_MSG, decrypted, frame_size);
        update_counter(timestamp);
        return 0;
    }
    print_error("Frame failed decryption...\n");
    return -1;
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


/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

 /**
 * @brief Main processing loop with command dispatch
 * 
 * This function:
 * 1. Initializes the system
 * 2. Continuously reads packets from the UART
 * 3. Dispatches commands to appropriate handler functions (LIST,DECODE,SUBSCRIBE)
 * 4. Sets LED status to indicate current operation
 * 
 */

int main(void) {
    char output_buf[MAX_UART_BUFFER_SIZE] = {0};
    uint8_t uart_buf[MAX_UART_BUFFER_SIZE];

    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    // Initialize TRNG 
    TRNG_Initialize();

    // process commands forever
    while (1) {
        STATUS_LED_GREEN();
        rand_delay();

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
            update_subscription(pkt_len, (encrypted_subscription_update_packet_t *)uart_buf);
            break;

        // Handle bad command
        default:
            STATUS_LED_ERROR();
            snprintf(output_buf, sizeof(output_buf), "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
