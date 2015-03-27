#ifndef OPENWRT_SUI_WIOMW_H
#define OPENWRT_SUI_WIOMW_H

#include <yajl/yajl_tree.h>
#include "xsrf.h"

void post_wiomw(yajl_val top, struct xsrft* token);

#endif
