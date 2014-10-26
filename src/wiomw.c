#include <config.h>
#include "wiomw_uci.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"

#define WIOMW_UCI_PATH "wiomw"
#define AGENT_UCI_PATH "wiomw.agent"
#define AGENT_ASSIGN_UCI_PATH AGENT_UCI_PATH "=wiomw-agent"
#define AGENTKEY_UCI_PATH "wiomw.agent.agentkey"
#define USERNAME_UCI_PATH "wiomw.agent.username"
#define PASSHASH_UCI_PATH "wiomw.agent.passhash"
#define AGENTKEY_PLACEHOLDER "openwrt-placeholder"

int assure_wiomw_uci_entry(struct uci_context* ctx)
{
	struct uci_ptr ptr;
	int res = 0;
	char* uci_string = strdup(WIOMW_UCI_PATH);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_string, true)) == UCI_ERR_NOTFOUND) {
		FILE* devnull = fopen("/dev/null", "r");
		res = uci_import(ctx, devnull, uci_string, NULL, true);
		fclose(devnull);
	} else if (res != UCI_OK) {
		free(uci_string);
		return res;
	}
	free(uci_string);
	uci_string = strdup(AGENT_UCI_PATH);
	if ((res = uci_lookup_ptr(ctx, &ptr, (uci_string = strdup(AGENT_ASSIGN_UCI_PATH)), true)) == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK) {
		uci_commit(ctx, &(ptr.p), true);
	}
	free(uci_string);
	return res;
}

void post_wiomw(yajl_val top)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* agentkey_yajl_path[] = {"agentkey", (const char*)0};
	const char* username_yajl_path[] = {"username", (const char*)0};
	const char* passhash_yajl_path[] = {"passhash", (const char*)0};
	yajl_val agentkey_yajl = yajl_tree_get(top, agentkey_yajl_path, yajl_t_string);
	yajl_val username_yajl = yajl_tree_get(top, username_yajl_path, yajl_t_string);
	yajl_val passhash_yajl = yajl_tree_get(top, passhash_yajl_path, yajl_t_string);
	bool valid = true;
	char agentkey[BUFSIZ];
	char username[BUFSIZ];
	char passhash[BUFSIZ];
	agentkey[0] = '\0';
	username[0] = '\0';
	passhash[0] = '\0';
	if (agentkey_yajl != NULL) {
		/* TODO: validate */
		strncpy(agentkey, YAJL_GET_STRING(agentkey_yajl), BUFSIZ);
	}
	if (username_yajl != NULL) {
		/* TODO: validate */
		strncpy(username, YAJL_GET_STRING(username_yajl), BUFSIZ);
	}
	if (passhash_yajl != NULL) {
		/* TODO: validate */
		strncpy(passhash, YAJL_GET_STRING(passhash_yajl), BUFSIZ);
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	if (valid && (strnlen(agentkey, BUFSIZ) != 0 || strnlen(username, BUFSIZ) != 0)) {
		if ((res = assure_wiomw_uci_entry(ctx)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to access UCI package for wiomw.\"]}");
			return;
		} else {
			if (strnlen(agentkey, BUFSIZ) != 0) {
				snprintf(uci_lookup_str, BUFSIZ, "%s=%s", AGENTKEY_UCI_PATH, agentkey);
				if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_set(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to save agentkey to UCI.\"]}");
					return;
				}
			}
			if (strnlen(username, BUFSIZ) != 0) {
				snprintf(uci_lookup_str, BUFSIZ, "%s=%s", USERNAME_UCI_PATH, username);
				if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_set(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to save username to UCI.\"]}");
					return;
				}
			}
			/*if (strnlen(passhash, BUFSIZ) != 0) {*/
				snprintf(uci_lookup_str, BUFSIZ, "%s=%s", PASSHASH_UCI_PATH, passhash);
				if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_set(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to save passhash to UCI.\"]}");
					return;
				}
			/*}*/
			res = uci_commit(ctx, &(ptr.p), true);
		}
	}

	agentkey[0] = '\0';
	username[0] = '\0';
	passhash[0] = '\0';

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
	strncpy(uci_lookup_str, USERNAME_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(username, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The username has not yet been set in UCI.\""); */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve username from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, PASSHASH_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(passhash, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The passhash has not yet been set in UCI.\""); */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve passhash from UCI.\"]}");
		return;
	}

	char data[BUFSIZ];
	char* tdata = data;
	size_t datalen = BUFSIZ;
	data[0] = '\0';

	if (strnlen(agentkey, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"agentkey\":\"%s\"", agentkey);
	}
	if (strnlen(username, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"username\":\"%s\"", username);
	}
	if (strnlen(passhash, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"passhash\":\"%s\"", passhash);
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

