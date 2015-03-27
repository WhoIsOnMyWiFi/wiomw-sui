#ifndef OPENWRT_SUI_URANDOM_H
#define OPENWRT_SUI_URANDOM_H

#include <stddef.h>

int urandom(unsigned char* data, size_t len);

#endif
