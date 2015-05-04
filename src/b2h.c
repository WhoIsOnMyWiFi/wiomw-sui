#include <config.h>
#include "b2h.h"

#include <stddef.h>

void b2h(char* dst, const unsigned char* const src, const size_t len)
{
	const char* const vals = "0123456789ABCDEF";

	size_t i = 0;

	for (i = 0; i < len; i++) {
		dst[(2 * i) + 0] = vals[src[i] >> 4];
		dst[(2 * i) + 1] = vals[src[i] & 0x0F];
	}

	return;
}

