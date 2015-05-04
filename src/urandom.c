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

