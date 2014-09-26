#include <config.h>
#include "wiomw_uci.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>

#define WIOMW_UCI_STRING "wiomw"
#define AGENT_UCI_STRING "wiomw.agent=wiomw-agent"
#define AGENTKEY_UCI_STRING "wiomw.agent.agentkey"
#define USERNAME_UCI_STRING "wiomw.agent.username"
#define PASSHASH_UCI_STRING "wiomw.agent.passhash"
#define AGENTKEY_PLACEHOLDER "openwrt-placeholder"

int create_wiomw_uci_entry(struct uci_context* ctx)
{
	struct uci_ptr ptr;
	int res = 0;
	if ((res = uci_lookup_ptr(ctx, &ptr, AGENT_UCI_STRING, true)) == UCI_ERR_NOTFOUND) {
		FILE* devnull = fopen("/dev/null", "r");
		res = uci_import(ctx, devnull, WIOMW_UCI_STRING, NULL, true);
		fclose(devnull);
		if (res == UCI_OK) {
			res = uci_lookup_ptr(ctx, &ptr, AGENT_UCI_STRING, true);
		}
	}
	if (res == UCI_OK && (res = uci_set(ctx, &ptr)) == UCI_OK) {
		res = uci_save(ctx, ptr.p);
	}
	return res;
}

int set_wiomw_agentkey(const char* agentkey)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* agentkey_path = strdup(AGENTKEY_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", agentkey_path, agentkey);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_string, true)) == UCI_ERR_NOTFOUND) {
		if ((res = create_wiomw_uci_entry(ctx)) == UCI_OK) {
			res = uci_lookup_ptr(ctx, &ptr, uci_string, true);
		}
	}
	if (res == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK) {
		res = uci_commit(ctx, &(ptr.p), false);
	}
	uci_free_context(ctx);
	free(agentkey_path);
	return res;
}

int set_wiomw_username(const char* username)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* username_path = strdup(USERNAME_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", username_path, username);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_string, true)) == UCI_ERR_NOTFOUND) {
		if ((res = create_wiomw_uci_entry(ctx)) == UCI_OK) {
			res = uci_lookup_ptr(ctx, &ptr, uci_string, true);
		}
	}
	if (res == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK) {
		res = uci_commit(ctx, &(ptr.p), false);
	}
	uci_free_context(ctx);
	free(username_path);
	return res;
}

int set_wiomw_passhash(const char* passhash)
{
	char uci_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* passhash_path = strdup(PASSHASH_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_string, BUFSIZ, "%s=%s", passhash_path, passhash);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_string, true)) == UCI_ERR_NOTFOUND) {
		if ((res = create_wiomw_uci_entry(ctx)) == UCI_OK) {
			res = uci_lookup_ptr(ctx, &ptr, uci_string, true);
		}
	}
	if (res == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK) {
		res = uci_commit(ctx, &(ptr.p), false);
	}
	uci_free_context(ctx);
	free(passhash_path);
	return res;
}

int set_wiomw_vals(const char* agentkey, const char* username, const char* passhash)
{
	char uci_agentkey_string[BUFSIZ];
	char uci_username_string[BUFSIZ];
	char uci_passhash_string[BUFSIZ];
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char* agentkey_path = strdup(AGENTKEY_UCI_STRING);
	char* username_path = strdup(USERNAME_UCI_STRING);
	char* passhash_path = strdup(PASSHASH_UCI_STRING);
	ctx = uci_alloc_context();
	snprintf(uci_agentkey_string, BUFSIZ, "%s=%s", agentkey_path, agentkey);
	snprintf(uci_username_string, BUFSIZ, "%s=%s", username_path, username);
	snprintf(uci_passhash_string, BUFSIZ, "%s=%s", passhash_path, passhash);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_agentkey_string, true)) == UCI_ERR_NOTFOUND) {
		if ((res = create_wiomw_uci_entry(ctx)) == UCI_OK) {
			res =uci_lookup_ptr(ctx, &ptr, uci_agentkey_string, true);
		}
	}
	if (res == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK
			&& (res = uci_lookup_ptr(ctx, &ptr, uci_username_string, true)) == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK
			&& (res = uci_lookup_ptr(ctx, &ptr, uci_passhash_string, true)) == UCI_OK
			&& (res = uci_set(ctx, &ptr)) == UCI_OK
			&& (res = uci_save(ctx, ptr.p)) == UCI_OK) {
		uci_commit(ctx, &(ptr.p), false);
	}
	uci_free_context(ctx);
	free(passhash_path);
	free(username_path);
	free(agentkey_path);
	return res;
}

int get_wiomw_agentkey(char** agentkey)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* agentkey_path = strdup(AGENTKEY_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, agentkey_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*agentkey = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "wiomw agentkey not set in UCI");
		*agentkey = strdup(AGENTKEY_PLACEHOLDER);
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve wiomw agentkey from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve wiomw agentkey from UCI: %s", *temp_str);
		}
	}
	return status;
}

int get_wiomw_username(char** username)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* username_path = strdup(USERNAME_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, username_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*username = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "wiomw username not set in UCI");
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve wiomw username from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve wiomw username from UCI: %s", *temp_str);
		}
	}
	return status;
}

int get_wiomw_passhash(char** passhash)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* passhash_path = strdup(PASSHASH_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, passhash_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*passhash = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "wiomw passhash not set in UCI");
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve wiomw passhash from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve wiomw passhash from UCI: %s", *temp_str);
		}
	}
	return status;
}

int get_wiomw_vals(char** agentkey, char** username, char** passhash)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	char* agentkey_path = strdup(AGENTKEY_UCI_STRING);
	char* username_path = strdup(USERNAME_UCI_STRING);
	char* passhash_path = strdup(PASSHASH_UCI_STRING);
	int status;
	ctx = uci_alloc_context();
	status = uci_lookup_ptr(ctx, &ptr, agentkey_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*agentkey = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "wiomw agentkey not set in UCI");
		*agentkey = strdup(AGENTKEY_PLACEHOLDER);
		return status;
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve wiomw agentkey from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve wiomw agentkey from UCI: %s", *temp_str);
		}
		return status;
	}
	status = uci_lookup_ptr(ctx, &ptr, username_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*username = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "wiomw username not set in UCI");
		return status;
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve wiomw username from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve wiomw username from UCI: %s", *temp_str);
		}
		return status;
	}
	status = uci_lookup_ptr(ctx, &ptr, passhash_path, true);
	if (status == UCI_OK) {
		if ((ptr.flags & UCI_LOOKUP_COMPLETE) && 0 < strlen(ptr.o->v.string)) {
			*passhash = strdup(ptr.o->v.string);
		}
	} else if (status == UCI_ERR_NOTFOUND) {
		fprintf(stderr, "wiomw passhash not set in UCI");
		return status;
	} else {
		char** temp_str = NULL;
		uci_get_errorstr(ctx, temp_str, "");
		if (temp_str == NULL || *temp_str == NULL) {
			fprintf(stderr, "Unable to retrieve wiomw passhash from UCI");
		} else {
			fprintf(stderr, "Unable to retrieve wiomw passhash from UCI: %s", *temp_str);
		}
		return status;
	}
}

