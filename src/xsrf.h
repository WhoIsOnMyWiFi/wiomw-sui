#ifndef OPENWRT_SUI_XSRF_H
#define OPENWRT_SUI_XSRF_H

#define XSRF_SOCK_PATH "/var/run/xsrfd.sock"
#define XSRF_TOKEN_BINARY_LENGTH 24
#define XSRF_TOKEN_HEX_LENGTH XSRF_TOKEN_BINARY_LENGTH * 2

struct xsrft {
	char val[XSRF_TOKEN_HEX_LENGTH + 1];
};

#endif
