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
#include "tmr_regs.h"
#include "tmr.h"

#include "simple_uart.h"
#include "simple_crypto.h"
#include "secrets.h"

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

// This is now defined in secrets.h
// #define MAX_CHANNEL_COUNT 8
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
    uint64_t timestamp; 
    uint8_t nonce[12];
    uint8_t ciphertext[64]; 
    uint8_t tag[16];
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

mxc_tmr_cfg_t tmr;

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

/** @brief
 * 
 *  @param timestamp The timestamp of the new frame
 *  @return 1 if timestamp is authentic and monotonically increasing
 */
int verify_timestamp(timestamp_t timestamp) {
    // Counter from memory
    uint64_t m_counter0 = (uint64_t) MXC_TMR_GetCount(MXC_TMR0);
    uint64_t m_counter1 = (uint64_t) MXC_TMR_GetCount(MXC_TMR1);

    uint64_t m_counter = (m_counter0 << 32) + m_counter1; 

    // Check timestamp sequence (increment only forward) 
    if (timestamp > m_counter) { 
        uint32_t timestamp0 = (uint32_t) (timestamp >> 32);
        uint32_t timestamp1 = (uint32_t) (timestamp & 0xFFFFFFFF);

        MXC_TMR_SetCount(MXC_TMR0, timestamp0);
        MXC_TMR_SetCount(MXC_TMR1, timestamp1);
        return 1;
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

    frame_size = pkt_len - (sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + sizeof(new_frame->nonce)
         + sizeof(new_frame->tag));
    channel = new_frame->channel;

    timestamp_t timestamp = new_frame->timestamp;

    // Verify timestamp
    if (verify_timestamp(timestamp)) {
        print_debug("Timestamp valid\n");
    } else {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Timestamp out of order.  %u\n", timestamp);
        print_error(output_buf);
        return -1; 
    }

    uint8_t aad[12]; 
    memcpy(aad, &channel, sizeof(channel));
    memcpy(aad + sizeof(channel), &timestamp, sizeof(timestamp));

    print_debug("Checking subscription\n");
    if (!is_subscribed(channel, timestamp)) {
        STATUS_LED_RED();
        sprintf(
            output_buf,
            "Receiving unsubscribed channel data or timestamp invalid.  %u\n", channel);
        print_error(output_buf);
        return -1;
    }

    uint8_t *decryption_key = get_channel_key(channel);

    // Buffer for decrypted output
    uint8_t decrypted[frame_size];

    print_debug("Using ChaCha Key for Channel:");
    printf("%u\n", channel);
    print_hex_debug(decryption_key, 32);

    int decrypt_sym(uint8_t *polyKey, uint8_t *polyIV, uint8_t *inAAD, uint32_t inADDlen, uint8_t *ciphertext, 
                uint32_t cipher_len, uint8_t *authTag, uint8_t *plaintext);
    print_debug("Decrypt operation details:\n");

    sprintf(output_buf, "AAD (%zu bytes): ", sizeof(aad));
    print_debug(output_buf);
    print_hex_debug(aad, sizeof(aad));
    print_debug("\n");

    print_debug("Decryption key: ");
    print_hex_debug(decryption_key, 32);
    print_debug("\n");

    print_debug("Nonce: ");
    print_hex_debug(new_frame->nonce, 12);
    print_debug("\n");

    print_debug("Ciphertext: ");
    print_hex_debug(new_frame->ciphertext, frame_size);
    print_debug("\n");

    sprintf(output_buf, "Frame size: %u bytes\n", frame_size);
    print_debug(output_buf);

    print_debug("Auth tag: ");
    print_hex_debug(new_frame->tag, 16);
    print_debug("\n");

    int decrypt_status = decrypt_sym(decryption_key, new_frame->nonce, aad, 12, new_frame->ciphertext,
            frame_size, new_frame->tag, decrypted);

    // sprintf(output_buf, "Decryption status: %d\n", decrypt_status);
    // print_debug(output_buf);

    if (decrypt_status == 0) {
        // print_debug("Decrypted data: ");
        // print_hex_debug(decrypted, frame_size);
        // print_debug("\n");
        write_packet(DECODE_MSG, decrypted, frame_size);
    }
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

    // Initialize counter
    MXC_TMR_Shutdown(MXC_TMR0);
    MXC_TMR_Shutdown(MXC_TMR1);

    tmr.bitMode = MXC_TMR_BIT_MODE_32;
    tmr.clock = MXC_TMR_APB_CLK; 
    tmr.cmp_cnt = 0xFFFFFFFF;
    tmr.mode = MXC_TMR_MODE_CAPTURE;
    tmr.pol = 1;
    tmr.pres = 0;

    MXC_TMR_Init(MXC_TMR0, &tmr, true);
    MXC_TMR_Init(MXC_TMR1, &tmr, true);
    MXC_TMR_SetCount(MXC_TMR0, 0);
    MXC_TMR_SetCount(MXC_TMR1, 0);
}


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
