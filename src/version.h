#ifndef WIOMW_SUI_VERSION_H
#define WIOMW_SUI_VERSION_H

#include <yajl/yajl_tree.h>
#include "xsrf.h"

void post_version(yajl_val top, struct xsrft* token);
int version_compare(char* new_version);

#endif
