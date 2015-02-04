#include <config.h>
#include "wiomw_uci.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"

#define MAX_SSID_LENGTH 32
#define MIN_PSK_LENGTH 8
#define MAX_PSK_LENGTH 63

#define SSID_UCI_PATH "wireless.@wifi-iface[0].ssid"
#define PSK_UCI_PATH "wireless.@wifi-iface[0].key"
#define ENCRYPTION_MODE_UCI_PATH "wireless.@wifi-iface[0].encryption"
#define WPA2_ONLY_ENCRYPTION_MODE "psk2+ccmp"
#define WIFI_DISABLED_UCI_PATH "wireless.@wifi-device[0].disabled"
#define WIFI_CHANGED_UCI_PATH "sui.changed.wifi"

#define DUAL_RADIO_UCI_PATH "sui.system.dualradio"
#define DUAL_SSID_UCI_PATH "wireless.@wifi-iface[1].ssid"
#define DUAL_PSK_UCI_PATH "wireless.@wifi-iface[1].key"
#define DUAL_ENCRYPTION_MODE_UCI_PATH "wireless.@wifi-iface[1].encryption"
#define DUAL_WIFI_DISABLED_UCI_PATH "wireless.@wifi-device[1].disabled"

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
		char* tstr = YAJL_GET_STRING(ssid_yajl);
		if (tstr != NULL) {
			register size_t i = 0;
			for (i = 0; tstr[i] != '\0' && i < MAX_SSID_LENGTH + 1; i++) {
				if (tstr[i] < 0x20 || tstr[i] > 0x7E) {
					printf("Status: 422 Unprocessable Entity\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"An SSID is currently limited to up to %d printable ASCII characters.\"]}", MAX_SSID_LENGTH);
					return;
				}
			}
			if (i > MAX_SSID_LENGTH) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"An SSID is currently limited to up to %d printable ASCII characters.\"]}", MAX_SSID_LENGTH);
				return;
			}
			strncpy(ssid, tstr, BUFSIZ);
		}
	}
	if (psk_yajl != NULL) {
		char* tstr = YAJL_GET_STRING(psk_yajl);
		if (tstr != NULL) {
			register size_t i = 0;
			for (i = 0; tstr[i] != '\0' && i < MAX_PSK_LENGTH + 1; i++) {
				if (tstr[i] < 0x20 || tstr[i] > 0x7E) {
					printf("Status: 422 Unprocessable Entity\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"A PSK is currently limited to between %d and %d printable ASCII characters.\"]}", MIN_PSK_LENGTH, MAX_PSK_LENGTH);
					return;
				}
			}
			if (i < MIN_PSK_LENGTH || i > MAX_PSK_LENGTH) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"A PSK is currently limited to between %d and %d printable ASCII characters.\"]}", MIN_PSK_LENGTH, MAX_PSK_LENGTH);
				return;
			}
			strncpy(psk, tstr, BUFSIZ);
		}
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	if (valid && (strnlen(ssid, BUFSIZ) != 0 || strnlen(psk, BUFSIZ) != 0)) {
		bool psk_changed = false;
		bool dual_radios = false;

		strcpy(uci_lookup_str, DUAL_RADIO_UCI_PATH);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to retrieve the number of wifi cards effected.\"]}");
			return;
		} else if ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0 && strncmp(ptr.o->v.string, "1", 2) == 0) {
			dual_radios = true;
		} else {
			dual_radios = false;
		}

		if (strnlen(ssid, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, SSID_UCI_PATH "=%s", ssid);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save ssid to UCI.\"]}");
				return;
			}
			if (dual_radios) {
				snprintf(uci_lookup_str, BUFSIZ, DUAL_SSID_UCI_PATH "=%s", ssid);
				if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_set(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to save ssid of second wifi radio to UCI.\"]}");
					return;
				}
			}
		}
		if (strnlen(psk, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, PSK_UCI_PATH "=%s", psk);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save psk to UCI.\"]}");
				return;
			}
			if (dual_radios) {
				snprintf(uci_lookup_str, BUFSIZ, DUAL_PSK_UCI_PATH "=%s", psk);
				if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_set(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to save psk of second wifi radio to UCI.\"]}");
					return;
				}
			}
			psk_changed = true;
		}
		strcpy(uci_lookup_str, ENCRYPTION_MODE_UCI_PATH "=" WPA2_ONLY_ENCRYPTION_MODE);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save WPA2 mode to UCI.\"]}");
			return;
		}
		strcpy(uci_lookup_str, WIFI_DISABLED_UCI_PATH);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0
					&& ((res = uci_delete(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p)) != UCI_OK))) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save wifi autostart to UCI.\"]}");
			return;
		}
		if (dual_radios) {
			strcpy(uci_lookup_str, DUAL_ENCRYPTION_MODE_UCI_PATH "=" WPA2_ONLY_ENCRYPTION_MODE);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WPA2 mode of second wifi radio to UCI.\"]}");
				return;
			}
			strcpy(uci_lookup_str, DUAL_WIFI_DISABLED_UCI_PATH);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0
						&& ((res = uci_delete(ctx, &ptr)) != UCI_OK
							|| (res = uci_save(ctx, ptr.p)) != UCI_OK))) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save wifi autostart of second wifi radio to UCI.\"]}");
				return;
			}
		}
		if ((res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save WiFi to UCI.\"]}");
			return;
		}
		strcpy(uci_lookup_str, WIFI_CHANGED_UCI_PATH "=1");
		if (psk_changed
				&& ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_set(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p)) != UCI_OK
						|| (res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK)) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to set WiFi as having been setup.\"]}");
			return;
		}
	}

	ssid[0] = '\0';
	psk[0] = '\0';

	strncpy(uci_lookup_str, SSID_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(ssid, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/*astpnprintf(&terrors, &errlen, ",\"The ssid has not yet been set in UCI.\"");*/
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve ssid from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, PSK_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(psk, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/*astpnprintf(&terrors, &errlen, ",\"The psk has not yet been set in UCI.\"");*/
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve psk from UCI.\"]}");
		return;
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
		return;
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

