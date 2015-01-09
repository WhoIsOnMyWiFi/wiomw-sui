#ifndef WIOMW_RANGE_CHECK_H
#define WIOMW_RANGE_CHECK_H

#include <stdbool.h>
#include <stdint.h>

bool ip4_check_range(uint32_t a, uint32_t amask, uint32_t b, uint32_t bmask);

#endif
