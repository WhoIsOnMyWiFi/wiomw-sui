#include <config.h>
#include "wiomw.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <curl/curl.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"
#include "xsrf.h"
#include "xsrfc.h"

#define AGENTKEY_UCI_PATH "wiomw.agent.agentkey"
#define PUBTOKEN_UCI_PATH "wiomw.agent.pubtoken"
#define PRIVTOKEN_UCI_PATH "wiomw.agent.privtoken"
#define AGENTKEY_PLACEHOLDER "openwrt-placeholder"
#define PIN_UCI_PATH "sui.system.pin"

#define WIOMW_AUTH_URL "https://www.whoisonmywifi.net/api/v100/rest/router_auth"
#define CA_FILE "/etc/ssl/certs/f081611a.0"

#define MAX_AUTHTOKEN_LENGTH 1024
#define MAX_PUBTOKEN_LENGTH 1024
#define MAX_PRIVTOKEN_LENGTH 4096
#define MAX_AGENTKEY_LENGTH 1024

struct data_holder {
	size_t offset;
	char data[];
};

static size_t get_data_cb(void* buffer, size_t size, size_t nmemb, void* raw_holder)
{
	size_t count = 0;
	struct data_holder* holder;

	if (raw_holder == NULL) {
		return 0;
	}

	if (*(void**)raw_holder == NULL) {
		*(void**)raw_holder = malloc(sizeof(struct data_holder) + (size * nmemb) + 1);
		(*(struct data_holder**)raw_holder)->offset = 0;
	} else {
		*(void**)raw_holder = realloc(*(void**)raw_holder, sizeof(struct data_holder) + (*(struct data_holder**)raw_holder)->offset + (size * nmemb) + 1);
	}
	holder = *(struct data_holder**)raw_holder;
	if (holder == NULL) {
		return 0;
	}

	for (count = 0; count < nmemb; count++) {
		memcpy(holder->data + holder->offset, (char*)buffer + (count * size), size);
		holder->offset += size;
	}
	holder->data[holder->offset] = '\0';

	return count * size;
}

static struct data_holder*  go_auth(char* const data)
{
	CURL* curl_handle = curl_easy_init();
	struct data_holder* holder = NULL;
	char error_buffer[BUFSIZ];
	long http_code = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, WIOMW_AUTH_URL);
	curl_easy_setopt(curl_handle, CURLOPT_CAINFO, CA_FILE);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &get_data_cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &holder);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);
	curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDSIZE, strlen(data));
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, error_buffer);

	if (curl_easy_perform(curl_handle) == 0 && curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code) == 0) {
		if (holder == NULL) {
			curl_easy_cleanup(curl_handle);
			free(holder);
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"The router is out of memory and needs to be restarted immediately.\"]}");
			syslog(LOG_EMERG, "Unable to allocate memory");
			return NULL;
		} else if (http_code == 403) {
			curl_easy_cleanup(curl_handle);
			free(holder);
			printf("Status: 403 Forbidden\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"The provided authtoken was invalid.\"]}");
			return NULL;
		} else if (http_code >= 400) {
			curl_easy_cleanup(curl_handle);
			free(holder);
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while contacting authentication server.\"]}");
			syslog(LOG_WARNING, "Unable to post to authentication API, got HTTP code: %lu", http_code);
			return NULL;
		} else {
			curl_easy_cleanup(curl_handle);
			return holder;
		}
	} else {
		/* curl failure (probably network failure) */
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Error while contacting authentication server.\"]}");
		syslog(LOG_ERR, "Unable to connect to authentication server: %s", error_buffer);
		curl_easy_cleanup(curl_handle);
		return NULL;
	}
}

void post_wiomw(yajl_val top)
{
	const char* authtoken_top_yajl_path[] = {"authtoken", (const char*)0};
	yajl_val authtoken_top_yajl = yajl_tree_get(top, authtoken_top_yajl_path, yajl_t_string);
	char authtoken[BUFSIZ];

	if (authtoken_top_yajl != NULL) {
		char* tstr = YAJL_GET_STRING(authtoken_top_yajl);
		if (tstr != NULL) {
			register size_t i = 0;
			for (i = 0; tstr[i] != '\0' && i < MAX_AUTHTOKEN_LENGTH + 1; i++) {
				if (tstr[i] < 0x20 || tstr[i] > 0x7E) {
					printf("Status: 422 Unprocessable Entity\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"An authtoken is currently limited to up to %d printable ASCII characters.\"]}", MAX_AUTHTOKEN_LENGTH);
					return;
				}
			}
			if (i > MAX_AUTHTOKEN_LENGTH) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"An authtoken is currently limited to up to %d printable ASCII characters.\"]}", MAX_AUTHTOKEN_LENGTH);
				return;
			}
			strncpy(authtoken, tstr, BUFSIZ);
		}
	} else {
		printf("Status: 422 Unprocessable Entity\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"An authtoken is required.\"]}");
		return;
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();
	char agentkey[BUFSIZ];
	char pubtoken[BUFSIZ];
	char privtoken[BUFSIZ];
	char pin[BUFSIZ];
	struct xsrft token;
	agentkey[0] = '\0';
	pubtoken[0] = '\0';
	privtoken[0] = '\0';
	pin[0] = '\0';
	token.val[0] = (char)0x00; /* yes i know it's the same... but this searching for xsrf stuff faster */

	strncpy(uci_lookup_str, AGENTKEY_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
			&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(agentkey, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The agentkey has not yet been set in UCI.\""); */
		strncpy(agentkey, AGENTKEY_PLACEHOLDER, BUFSIZ);
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve agentkey from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, PUBTOKEN_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
			&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(pubtoken, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The pubtoken has not yet been set in UCI.\""); */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve public token from UCI.\"]}");
		return;
	}
	if (pubtoken != NULL) {
		strncpy(uci_lookup_str, PRIVTOKEN_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
				&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
			strncpy(privtoken, ptr.o->v.string, BUFSIZ);
		} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
			/* astpnprintf(&terrors, &errlen, ",\"The privtoken has not yet been set in UCI.\""); */
		} else {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to retrieve private token from UCI.\"]}");
			return;
		}

		if (privtoken == NULL) {
			int xsrfc_status = -1;
			strncpy(uci_lookup_str, PIN_UCI_PATH, BUFSIZ);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
					&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
				strncpy(pin, ptr.o->v.string, BUFSIZ);
			} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
				/* Pin has not been set in UCI??? No good! */
				syslog(LOG_CRIT, "Pin has not been set in UCI at " PIN_UCI_PATH);
			} else {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to retrieve pin from UCI.\"]}");
				return;
			}
			token.val[0] = (char)0x00;
			if ((xsrfc_status = xsrfc(&token)) <= 0) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to connect to internal login system.\"]}");
				return;
			}
		}
	}

	char data[BUFSIZ];

	if (pubtoken == NULL) {
		snprintf(data, BUFSIZ, "{\"authtoken\":\"%s\"}", authtoken);
	} else if (privtoken == NULL) {
		snprintf(data, BUFSIZ, "{\"authtoken\":\"%s\",\"pubtoken\":\"%s\",\"agentkey\":\"%s\",\"pin\":\"%s\",\"xsrf\":\"%s\"}", authtoken, pubtoken, agentkey, pin, token.val);
	} else {
		snprintf(data, BUFSIZ, "{\"authtoken\":\"%s\",\"pubtoken\":\"%s\",\"privtoken\":\"%s\",\"agentkey\":\"%s\"}", authtoken, pubtoken, privtoken, agentkey);
	}

	struct data_holder* holder = NULL;
	
	if ((holder = go_auth(data)) == NULL) {
		return;
	}

	char error_buffer[BUFSIZ];
	yajl_val response_yajl = NULL;

	if ((response_yajl = yajl_tree_parse(holder->data, error_buffer, BUFSIZ)) == NULL || !YAJL_IS_OBJECT(response_yajl)) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Received unexpected response from login server.\"");
		return;
	}

	const char* pubtoken_yajl_path[] = {"pubtoken", (const char*)0};
	const char* privtoken_yajl_path[] = {"privtoken", (const char*)0};
	const char* agentkey_yajl_path[] = {"agentkey", (const char*)0};
	const char* authenticated_yajl_path[] = {"authenticated", (const char*)0};
	const char* authtoken_yajl_path[] = {"authtoken", (const char*)0};
	yajl_val pubtoken_yajl = yajl_tree_get(response_yajl, pubtoken_yajl_path, yajl_t_string);
	yajl_val privtoken_yajl = yajl_tree_get(response_yajl, privtoken_yajl_path, yajl_t_string);
	yajl_val agentkey_yajl = yajl_tree_get(response_yajl, agentkey_yajl_path, yajl_t_string);
	yajl_val authenticated_yajl = yajl_tree_get(response_yajl, authenticated_yajl_path, yajl_t_true);
	yajl_val authtoken_yajl = yajl_tree_get(response_yajl, authtoken_yajl_path, yajl_t_string);
	char* pubtoken_val = YAJL_GET_STRING(pubtoken_yajl);
	char* privtoken_val = YAJL_GET_STRING(privtoken_yajl);
	char* agentkey_val = YAJL_GET_STRING(agentkey_yajl);
	char* authtoken_val = YAJL_GET_STRING(authtoken_yajl);
	bool changed = false;

	if (pubtoken_val != NULL && stpncpy(pubtoken, pubtoken_val, BUFSIZ) != pubtoken + BUFSIZ && pubtoken[0] != '\0') {
		snprintf(uci_lookup_str, BUFSIZ, PUBTOKEN_UCI_PATH "=%s", pubtoken);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save pubtoken to UCI.\"]}");
			return;
		} else {
			changed = true;
		}
	}
	if (privtoken_val != NULL && stpncpy(privtoken, privtoken_val, BUFSIZ) != privtoken + BUFSIZ && privtoken[0] != '\0') {
		snprintf(uci_lookup_str, BUFSIZ, PRIVTOKEN_UCI_PATH "=%s", privtoken);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save privtoken to UCI.\"]}");
			return;
		} else {
			changed = true;
		}
	}
	if (agentkey_val != NULL && stpncpy(agentkey, agentkey_val, BUFSIZ) != agentkey + BUFSIZ && agentkey[0] != '\0') {
		snprintf(uci_lookup_str, BUFSIZ, AGENTKEY_UCI_PATH "=%s", agentkey);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save agentkey to UCI.\"]}");
			return;
		} else {
			changed = true;
		}
	}
	if (changed) {
		if ((res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save wiomw credentials to UCI.\"]}");
			return;
		}
	}

	if (authtoken_val != NULL && stpncpy(authtoken, authtoken_val, BUFSIZ) != authtoken + BUFSIZ) {
		printf("Status: 200 OK\n");
		printf("Content-type: application/json\n\n");
		printf("{\"authtoken\":\"%s\"}", authtoken);
		return;
	} else if (authenticated_yajl != NULL && YAJL_IS_TRUE(authenticated_yajl)) {
		int xsrfc_status = -1;
		token.val[0] = (char)0x00;
		if ((xsrfc_status = xsrfc(&token)) <= 0) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to communicate with internal login system.\"]}");
			return;
		} else {
			printf("Status: 200 OK\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\"}", token.val);
			return;
		}
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Received unexpected response from login server..\"]}");
		return;
	}
}

