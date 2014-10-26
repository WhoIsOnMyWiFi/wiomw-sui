#include <config.h>
#include "wiomw_uci.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"

#define SSID_UCI_PATH "wireless.@wifi-iface[0].ssid"
#define PSK_UCI_PATH "wireless.@wifi-iface[0].key"

void post_wifi(yajl_val top)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* ssid_yajl_path[] = {"ssid", (const char*)0};
	const char* psk_yajl_path[] = {"psk", (const char*)0};
	yajl_val ssid_yajl = yajl_tree_get(top, ssid_yajl_path, yajl_t_string);
	yajl_val psk_yajl = yajl_tree_get(top, psk_yajl_path, yajl_t_string);
	bool valid = true;
	char ssid[BUFSIZ];
	char psk[BUFSIZ];
	ssid[0] = '\0';
	psk[0] = '\0';
	if (ssid_yajl != NULL) {
		/* TODO: validate */
		strncpy(ssid, YAJL_GET_STRING(ssid_yajl), BUFSIZ);
	}
	if (psk_yajl != NULL) {
		/* TODO: validate */
		strncpy(psk, YAJL_GET_STRING(psk_yajl), BUFSIZ);
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	if (valid && (strnlen(ssid, BUFSIZ) != 0 || strnlen(psk, BUFSIZ) != 0)) {
		if (strnlen(ssid, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", SSID_UCI_PATH, ssid);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save ssid to UCI.\"]}");
				return;
			}
		}
		if (strnlen(psk, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", PSK_UCI_PATH, psk);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save psk to UCI.\"]}");
				return;
			}
		}
		res = uci_commit(ctx, &(ptr.p), true);
	}

	ssid[0] = '\0';
	psk[0] = '\0';

	strncpy(uci_lookup_str, SSID_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(ssid, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		astpnprintf(&terrors, &errlen, ",\"The ssid has not yet been set in UCI.\"");
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve ssid from UCI.\"]}");
	}
	strncpy(uci_lookup_str, PSK_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(psk, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		astpnprintf(&terrors, &errlen, ",\"The psk has not yet been set in UCI.\"");
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve psk from UCI.\"]}");
	}

	char data[BUFSIZ];
	char* tdata = data;
	size_t datalen = BUFSIZ;
	data[0] = '\0';

	if (strnlen(ssid, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"ssid\":\"%s\"", ssid);
	} else {
		astpnprintf(&terrors, &errlen, ",\"The ssid has not yet been set in UCI.\"");
	}
	if (strnlen(psk, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"psk\":\"%s\"", psk);
	} else {
		astpnprintf(&terrors, &errlen, ",\"The psk has not yet been set in UCI.\"");
	}

	if (datalen == BUFSIZ) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve any data from UCI.\"");
		if (errlen != BUFSIZ) {
			printf(",%s]}", errors + 1);
		} else {
			printf("]}");
		}
	} else if (!valid) {
		printf("Status: 422 Unprocessable Entity\n");
		printf("Content-type: application/json\n\n");
	} else {
		printf("Status: 200 OK\n");
		printf("Content-type: application/json\n\n");
	}

	printf("{%s", data + 1);
	if (errlen != BUFSIZ) {
		printf(",\"errors\":[%s]}", errors + 1);
	} else {
		printf("}");
	}

}

