#pragma once

/**
 * @author      smallfoot47
 * @file        check.cpp
 * @brief       Implementation of state-bound crc instance 
 */

/***** Includes *****/
#include "mxc_device.h"
#include "nvic_table.h"
#include "board.h"
#include "crc.h"
#include "dma.h"

/***** Definitions *****/
#define POLY    0xEDB88320
#define CHANNELS 8
#define CHANNEL_SIZE 16

/***** Classes *****/

unsigned int CRC_RESULTS[CHANNELS];

void CHECKER_INIT() {
    MXC_CRC_Init();
    MXC_CRC_SetPoly(POLY);

    for (short i = 0; i < CHANNELS; ++i)
    CRC_RESULTS[i] = 0u;
}

const uint32_t CRC_COMPUTE(uint32_t* memory) {
    mxc_crc_req_t crc_req = {
        memory,
        CHANNEL_SIZE,
        0
    };
    
    MXC_CRC_Compute(&crc_req);
    
    return crc_req.resultCRC;
}

void CHECKER_REMEMBER_CHANNEL(uint32_t* channel_location) {
    CRC_RESULTS[(memory / CHANNEL_SIZE) % CHANNELS] = CRC_COMPUTE(channel_location);
}

const bool CHECKER_VERIFY_CHANNEL(uint32_t* channel_location) {
    return CRC_COMPUTE(memory) == CRC_RESULTS[(memory / CHANNEL_SIZE) % CHANNELS];
}

void CHECKER_END() {
    MXC_CRC_Shutdown();
}

/*
    Usage:
        CHECKER_INIT(); // invoked initially
        ...
        // assuming channel1 stores channel 1's data
        CHECKER_REMEMBER_CHANNEL(&channel1);
        ...
        // channels talk
        ...
        // need to verify integrity of channel 1's data
        if (! CHECKER_VERIFY_CHANNEL(&channel1)) {
            // channel 1 compromised!
        }
        ...
        CHECKER_END(); // called when channels are no longer needed          
*/
// *****************************************************************************