#ifndef OPENWRT_SUI_DNS_H
#define OPENWRT_SUI_DNS_H

#include <yajl/yajl_tree.h>
#include "xsrf.h"

void post_dns(yajl_val top, struct xsrft* token);

#endif
