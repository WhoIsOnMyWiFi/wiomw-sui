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
#include "urandom.h"

#include <stddef.h>
#include <stdio.h>
#include <linux/random.h>
#include <sys/ioctl.h>

int urandom(unsigned char* data, size_t len)
{
	int entropy = 0;
	FILE* f = fopen("/dev/urandom", "r");
	if (f == NULL) {
		return -1;
	}
	if (ioctl(fileno(f), RNDGETENTCNT, &entropy) < 0) {
		return -1;
	}
	if (fread(data, len, 1, f) < 1) {
		return -1;
	}
	fclose(f);
	return entropy;
}

