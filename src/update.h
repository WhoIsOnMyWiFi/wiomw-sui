#ifndef WIOMW_SUI_UPDATE_H
#define WIOMW_SUI_UPDATE_H

#include <yajl/yajl_tree.h>
#include "xsrf.h"

void post_update(yajl_val top, struct xsrft* token);
void post_update_log(yajl_val top, struct xsrft* token);

#endif
