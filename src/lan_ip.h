#ifndef OPENWRT_SUI_LAN_IP_H
#define OPENWRT_SUI_LAN_IP_H

#include <stdbool.h>
#include <stdint.h>
#include <yajl/yajl_tree.h>

bool get_lan_ip4(uint32_t* base, uint32_t* netmask);

bool set_lan_ip4(const char* base, const char* netmask);

void post_lan_ip(yajl_val top);

#endif
