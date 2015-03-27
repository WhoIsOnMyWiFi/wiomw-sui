#ifndef OPENWRT_SUI_WIFI_H
#define OPENWRT_SUI_WIFI_H

#include <yajl/yajl_tree.h>
#include "xsrf.h"

void post_wifi(yajl_val top, struct xsrft* token);

#endif
