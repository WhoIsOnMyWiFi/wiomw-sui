#include <config.h>
#include "wifi_uci.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>

#define SSID_UCI_STRING "wireless.@wifi-iface[0].ssid"
#define PSK_UCI_STRING "wireless.@wifi-iface[0].key"

int set_wifi_ssid(const char* ssid)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* ssid_path = strdup(SSID_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", ssid_path, ssid);
	if ((res = uci_parse_ptr(ctx, &ptr, uci_string)) != 0) {
		return res;
	}
	res = uci_set(ctx, &ptr);
	uci_commit(ctx, &(ptr.p), true);
	uci_free_context(ctx);
	free(ssid_path);
	return res;
}

int set_wifi_psk(const char* psk)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* psk_path = strdup(PSK_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", psk_path, psk);
	if ((res = uci_parse_ptr(ctx, &ptr, uci_string)) != 0) {
		return res;
	}
	res = uci_set(ctx, &ptr);
	uci_commit(ctx, &(ptr.p), true);
	uci_free_context(ctx);
	free(psk_path);
	return res;
}

int set_wifi_vals(const char* ssid, const char* psk)
{
	char uci_ssid_string[BUFSIZ];
	char uci_psk_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* ssid_path = strdup(SSID_UCI_STRING);
	char* psk_path = strdup(PSK_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_ssid_string, BUFSIZ, "%s=%s", ssid_path, ssid);
	snprintf(uci_psk_string, BUFSIZ, "%s=%s", psk_path, psk);
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
	free(psk_path);
	free(ssid_path);
	return res;
}

int get_wifi_ssid(char** ssid)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* ssid_path = strdup(SSID_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, ssid_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*ssid = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "SSID not set in UCI");
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve SSID from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve SSID from UCI: %s", *temp_str);
		}
	}
	return status;
}

int get_wifi_psk(char** psk)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* psk_path = strdup(PSK_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, psk_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*psk = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "PSK not set in UCI");
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve PSK from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve PSK from UCI: %s", *temp_str);
		}
	}
	return status;
}

int get_wifi_vals(char** ssid, char** psk)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* ssid_path = strdup(SSID_UCI_STRING);
	char* psk_path = strdup(PSK_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, ssid_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*ssid = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "SSID not set in UCI");
		return status;
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve SSID from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve SSID from UCI: %s", *temp_str);
		}
		return status;
	}
	status = uci_lookup_ptr(ctx, &ptr, psk_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*psk = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "PSK not set in UCI");
		return status;
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve PSK from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve PSK from UCI: %s", *temp_str);
		}
		return status;
	}
}

