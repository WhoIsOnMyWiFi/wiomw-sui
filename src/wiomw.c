#include <config.h>
#include "wiomw_uci.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"

#define AGENTKEY_UCI_PATH "wiomw.agent.agentkey"
#define PUBTOKEN_UCI_PATH "wiomw.agent.pubtoken"
#define PRIVTOKEN_UCI_PATH "wiomw.agent.privtoken"
#define AGENTKEY_PLACEHOLDER "openwrt-placeholder"
#define WIOMW_CHANGED_UCI_PATH "sui.changed.wiomw"

void post_wiomw(yajl_val top)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* agentkey_yajl_path[] = {"agentkey", (const char*)0};
	const char* pubtoken_yajl_path[] = {"pubtoken", (const char*)0};
	const char* privtoken_yajl_path[] = {"privtoken", (const char*)0};
	yajl_val agentkey_yajl = yajl_tree_get(top, agentkey_yajl_path, yajl_t_string);
	yajl_val pubtoken_yajl = yajl_tree_get(top, pubtoken_yajl_path, yajl_t_string);
	yajl_val privtoken_yajl = yajl_tree_get(top, privtoken_yajl_path, yajl_t_string);
	bool valid = true;
	char agentkey[BUFSIZ];
	char pubtoken[BUFSIZ];
	char privtoken[BUFSIZ];
	agentkey[0] = '\0';
	pubtoken[0] = '\0';
	privtoken[0] = '\0';
	if (agentkey_yajl != NULL) {
		/* TODO: validate */
		strncpy(agentkey, YAJL_GET_STRING(agentkey_yajl), BUFSIZ);
	}
	if (pubtoken_yajl != NULL) {
		/* TODO: validate */
		strncpy(pubtoken, YAJL_GET_STRING(pubtoken_yajl), BUFSIZ);
	}
	if (privtoken_yajl != NULL) {
		/* TODO: validate */
		strncpy(privtoken, YAJL_GET_STRING(privtoken_yajl), BUFSIZ);
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	if (valid && (strnlen(agentkey, BUFSIZ) != 0 || strnlen(pubtoken, BUFSIZ) != 0)) {
		if (strnlen(agentkey, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, AGENTKEY_UCI_PATH "=%s", agentkey);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save agentkey to UCI.\"]}");
				return;
			}
		}
		if (strnlen(pubtoken, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, PUBTOKEN_UCI_PATH "=%s", pubtoken);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save pubtoken to UCI.\"]}");
				return;
			}
		}
		if (strnlen(privtoken, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, PRIVTOKEN_UCI_PATH "=%s", privtoken);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save privtoken to UCI.\"]}");
				return;
			}
		} else {
			strncpy(uci_lookup_str, PRIVTOKEN_UCI_PATH, BUFSIZ);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_delete(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to delete old privtoken from UCI.\"]}");
				return;
			}
		}
		strncpy(uci_lookup_str, WIOMW_CHANGED_UCI_PATH, BUFSIZ);
		if ((res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK
				|| (res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK
				|| (res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to save wiomw credentials to UCI.\"]}");
			return;
		}
	}

	agentkey[0] = '\0';
	pubtoken[0] = '\0';
	privtoken[0] = '\0';

	strncpy(uci_lookup_str, AGENTKEY_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(agentkey, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The agentkey has not yet been set in UCI.\""); */
		/* TODO: return default agentkey */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve agentkey from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, PUBTOKEN_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(pubtoken, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The pubtoken has not yet been set in UCI.\""); */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve public token from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, PRIVTOKEN_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(privtoken, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The privtoken has not yet been set in UCI.\""); */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve private token from UCI.\"]}");
		return;
	}

	char data[BUFSIZ];
	char* tdata = data;
	size_t datalen = BUFSIZ;
	data[0] = '\0';

	if (strnlen(agentkey, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"agentkey\":\"%s\"", agentkey);
	}
	if (strnlen(pubtoken, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"pubtoken\":\"%s\"", pubtoken);
	}
	/*
	if (strnlen(privtoken, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"privtoken\":\"%s\"", privtoken);
	}
	*/

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

