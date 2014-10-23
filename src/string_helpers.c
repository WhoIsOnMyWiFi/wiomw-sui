/**
 * Copyright 2013, 2014 Who Is On My WiFi.
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

#include "string_helpers.h"

#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdio.h>
#include <stdarg.h>

char* stpnprintf(char* str, size_t size, const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	vsnprintf(str, size, fmt, args);
	va_end(args);
	return str + strnlen(str, size);
}

void astpnprintf(char** str, size_t* size, const char* fmt, ...)
{
	va_list args;
	size_t newsiz = 0;
	va_start(args, fmt);
	vsnprintf(*str, *size, fmt, args);
	va_end(args);
	newsiz = strnlen(*str, *size);
	*str += newsiz;
	*size -= newsiz;
}

