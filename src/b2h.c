/**
 * Copyright 2014, 2015 Who Is On My WiFi.
 *
 * This file is part of Who Is On My WiFi Linux.
 *
 * Who Is On My WiFi Linux is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Who Is On My WiFi Linux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
 *
 * More information about Who Is On My WiFi Linux can be found at
 * <http://www.whoisonmywifi.com/>.
 */

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

