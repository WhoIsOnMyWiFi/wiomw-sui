#include <config.h>
#include "wifi.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>

#define SSID_UCI_STRING "wireless.@wifi-iface[0].ssid"
#define PSK_UCI_STRING "wireless.@wifi-iface[0].key"

int set_ssid(const char* ssid)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", SSID_UCI_STRING, ssid);
	if ((res = uci_parse_ptr(ctx, &ptr, uci_string)) != 0) {
		return res;
	}
	res = uci_set(ctx, &ptr);
	uci_commit(ctx, &(ptr.p), true);
	uci_free_context(ctx);
	return res;
}

int set_psk(const char* psk)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", PSK_UCI_STRING, psk);
	if ((res = uci_parse_ptr(ctx, &ptr, uci_string)) != 0) {
		return res;
	}
	res = uci_set(ctx, &ptr);
	uci_commit(ctx, &(ptr.p), true);
	uci_free_context(ctx);
	return res;
}

int set_vals(const char* ssid, const char* psk)
{
	char uci_ssid_string[BUFSIZ];
	char uci_psk_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	ctx = uci_alloc_context();
	snprintf(uci_ssid_string, BUFSIZ, "%s=%s", SSID_UCI_STRING, ssid);
	snprintf(uci_psk_string, BUFSIZ, "%s=%s", PSK_UCI_STRING, psk);
	if ((res = uci_parse_ptr(ctx, &ptr, uci_ssid_string)) != 0) {
		return res;
	}
	res = uci_set(ctx, &ptr);
	if ((res = uci_parse_ptr(ctx, &ptr, uci_psk_string)) != 0) {
		return res;
	}
	res = uci_set(ctx, &ptr);
	uci_commit(ctx, &(ptr.p), true);
	uci_free_context(ctx);
	return res;
}


