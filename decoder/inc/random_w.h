#ifndef RANDOM_DELAY_H
#define RANDOM_DELAY_H

#include <stdint.h>

/**
 * @brief Initialize the True Random Number Generator
 */
void TRNG_Initialize(void);

/**
 * @brief Create a millisecond delay
 * @param ms Number of milliseconds to delay
 */
void ms_delay(uint32_t ms);

/**
 * @brief Convert 4 bytes to a 32-bit integer (little-endian)
 * @param bytes Pointer to array of 4 bytes
 * @return 32-bit integer representation
 */
uint32_t bytes_to_int(uint8_t *bytes);

/**
 * @brief Generate a random delay using the TRNG
 */
void rand_delay(void);

#endif /* RANDOM_DELAY_H */