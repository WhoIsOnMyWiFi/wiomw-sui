#include <config.h>

#include "range_check.h"

#include <stdbool.h>
#include <stdint.h>

bool ip4_check_range(uint32_t a, uint32_t amask, uint32_t b, uint32_t bmask)
{
	return ((a ^ b) & ((amask <= bmask) ? amask : bmask)) == 0;
}

