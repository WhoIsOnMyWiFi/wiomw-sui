#ifndef OPENWRT_SUI_WAN_IP_H
#define OPENWRT_SUI_WAN_IP_H

#include <stdbool.h>
#include <stdint.h>
#include <yajl/yajl_tree.h>

bool get_wan_ip4(uint32_t* base, uint32_t* netmask);

void post_wan_ip(yajl_val top);

#endif
