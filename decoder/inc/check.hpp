#pragma once

/**
 * @author      smallfoot47
 * @file        check.cpp
 * @brief       Implementation of state-bound crc instance 
 */

/***** Includes *****/
#include <stdint.h>
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

namespace check {
    class CRC {
        private:
            uint32_t m_crc_results[CHANNELS];

        private:
            const uint32_t get_result(uint32_t* memory) {
                mxc_crc_req_t crc_req = {
                    memory,
                    CHANNEL_SIZE,
                    0
                };
            
                MXC_CRC_Compute(&crc_req);
                
                return crc_req.resultCRC;
            }

        public:
            CRC() {
                MXC_CRC_Init();
                MXC_CRC_SetPoly(POLY);

                for (uint32_t& val : m_crc_results)
                    val = 0u;
            }

            /**
             * @brief Computes CRC value at memory location
             */
            void remember(uint32_t* memory) {
                m_crc_results[(memory / CHANNEL_SIZE) % CHANNELS] = get_result(memory);
            }
            
            /**
             * @brief Verifies CRC value at memory location with precomputed value. Returns true of integrity holds, false otherwise
             */
            const bool verify(uint32_t* memory) {
                return get_result(memory) == m_crc_results[(memory / CHANNEL_SIZE) % CHANNELS];
            }

            ~CRC() {
                MXC_CRC_Shutdown();
            }
    };
}

/*
    Usage:
        check::CRC checker;

        checker.remember(channel_address1);

        // channel changes over time

        if (! checker.verify(channel_address1)) {
            // channel compromised, integrity check failed!
        }
*/
// *****************************************************************************