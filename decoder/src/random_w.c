#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mxc_device.h"
#include "mxc_delay.h"
#include "nvic_table.h"
#include "trng.h"
#include "random_w.h"

volatile int wait;
uint8_t random_src[4] = {0};

void TRNG_Initialize(void) {
    MXC_TRNG_Init();
}

void TRNG_IRQHandler(void)
{
    MXC_TRNG_Handler();
}

void ms_delay(uint32_t rand_delay)
{
    MXC_Delay(rand_delay);
}

uint32_t bytes_to_int(uint8_t *bytes) {
    return (uint32_t)(bytes[0]) | 
           ((uint32_t)(bytes[1]) << 8) | 
           ((uint32_t)(bytes[2]) << 16) | 
           ((uint32_t)(bytes[3]) << 24);
}

void rand_delay(void)
{
    uint32_t num_bytes = 4;
    
    memset(random_src, 0, sizeof(random_src));
    
    MXC_TRNG_Random(random_src, num_bytes);
    
    uint32_t rand_int = bytes_to_int(random_src);
    uint32_t rand_delay_range = 500 + (rand_int%4500);
    ms_delay(rand_delay_range); 
}