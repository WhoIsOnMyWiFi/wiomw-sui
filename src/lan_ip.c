#include <config.h>
#include "lan_ip.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"
#include "xsrf.h"

#define IPADDR_UCI_PATH "network.lan.ipaddr"
#define NETMASK_UCI_PATH "network.lan.netmask"
#define LAN_CHANGED_UCI_PATH "sui.changed.lan"

#define MAX_IP_LENGTH 32

bool set_lan_ip4(const char* base, const char* netmask)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	uint32_t dummy = 0;

	if (base == NULL
			|| netmask == NULL
			|| strlen(base) == 0
			|| strlen(netmask) == 0
			|| inet_pton(AF_INET, base, &dummy) != 1
			|| inet_pton(AF_INET, netmask, &dummy) != 1) {
		return false;
	}

	ctx = uci_alloc_context();

	snprintf(uci_lookup_str, BUFSIZ, IPADDR_UCI_PATH "=%s", base);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
			|| uci_set(ctx, &ptr) != UCI_OK
			|| uci_save(ctx, ptr.p) != UCI_OK) {
		return false;
	}

	snprintf(uci_lookup_str, BUFSIZ, NETMASK_UCI_PATH "=%s", netmask);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
			|| uci_set(ctx, &ptr) != UCI_OK
			|| uci_save(ctx, ptr.p) != UCI_OK) {
		return false;
	}

	if ((res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK) {
		return false;
	}

	return true;
}

/*
 * returns true if successful and LAN has never been changed
 */
bool get_lan_ip4(uint32_t* base, uint32_t* netmask)
{
	bool never_changed = true;
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	strncpy(uci_lookup_str, LAN_CHANGED_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK) {
		*base = 0;
		*netmask = 0;
		return false;
	} else if ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0) {
		never_changed = (atoi(ptr.o->v.string) != 1);
	}

	strncpy(uci_lookup_str, IPADDR_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
			|| (ptr.flags & UCI_LOOKUP_COMPLETE) == 0) {
		*base = 0;
		*netmask = 0;
		return false;
	} else if (inet_pton(AF_INET, ptr.o->v.string, base) != 1) {
		*base = 0;
		*netmask = 0;
		return false;
	}

	strncpy(uci_lookup_str, NETMASK_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
			|| (ptr.flags & UCI_LOOKUP_COMPLETE) == 0) {
		*base = 0;
		*netmask = 0;
		return false;
	} else if (inet_pton(AF_INET, ptr.o->v.string, netmask) != 1) {
		*base = 0;
		*netmask = 0;
		return false;
	}

	return never_changed;
}

void post_lan_ip(yajl_val top, struct xsrft* token)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* ipaddr_yajl_path[] = {"ip", (const char*)0};
	const char* netmask_yajl_path[] = {"netmask", (const char*)0};
	yajl_val ipaddr_yajl = yajl_tree_get(top, ipaddr_yajl_path, yajl_t_string);
	yajl_val netmask_yajl = yajl_tree_get(top, netmask_yajl_path, yajl_t_string);
	bool valid = true;
	char ipaddr[BUFSIZ];
	char netmask[BUFSIZ];
	ipaddr[0] = '\0';
	netmask[0] = '\0';
	/* TODO: be more forgiving about dhcp:1 and dhcp:"yes" and whatnot? */
	if (ipaddr_yajl != NULL) {
		char* tstr = YAJL_GET_STRING(ipaddr_yajl);
		if (tstr != NULL) {
			int res = 0;
			struct in_addr temp;
			if (tstr[0] == '\0'
					|| strnlen(tstr, MAX_IP_LENGTH + 1) > MAX_IP_LENGTH
					|| ((res = inet_pton(AF_INET, tstr, &temp)) == 0)) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"The LAN ip address is currently required to be an IPv4 address sent in dotted-quad notation.\"]}", token->val);
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to parse supplied LAN IPv4 address.\"]}", token->val);
				return;
			}
			strncpy(ipaddr, tstr, BUFSIZ);
		}
	}
	if (netmask_yajl != NULL) {
		char* tstr = YAJL_GET_STRING(netmask_yajl);
		if (tstr != NULL) {
			int res = 0;
			struct in_addr temp;
			if (tstr[0] == '\0'
					|| strnlen(tstr, MAX_IP_LENGTH + 1) > MAX_IP_LENGTH
					|| ((res = inet_pton(AF_INET, tstr, &temp)) == 0)) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"The LAN netmask is currently required to be an IPv4 netmask sent in dotted-quad notation.\"]}", token->val);
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to parse supplied LAN IPv4 netmask.\"]}", token->val);
				return;
			}
			strncpy(netmask, tstr, BUFSIZ);
		}
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	if (valid && (strnlen(ipaddr, BUFSIZ) != 0 || strnlen(netmask, BUFSIZ) != 0)) {
		if (strnlen(ipaddr, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, IPADDR_UCI_PATH "=%s", ipaddr);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save LAN IP address to UCI.\"]}", token->val);
				return;
			}
		}
		if (strnlen(netmask, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, NETMASK_UCI_PATH "=%s", netmask);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save LAN netmask to UCI.\"]}", token->val);
				return;
			}
		}

		strncpy(uci_lookup_str, LAN_CHANGED_UCI_PATH "=1", BUFSIZ);
		if ((res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK
				|| (res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK
				|| (res = uci_commit(ctx, &(ptr.p), true)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save LAN data to UCI.\"]}", token->val);
			return;
		}
	}

	ipaddr[0] = '\0';
	netmask[0] = '\0';

	strncpy(uci_lookup_str, IPADDR_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(ipaddr, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		astpnprintf(&terrors, &errlen, ",\"The LAN IP address has not yet been set in UCI.\"");
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve LAN IP address from UCI.\"]}", token->val);
		return;
	}
	strncpy(uci_lookup_str, NETMASK_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(netmask, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		astpnprintf(&terrors, &errlen, ",\"The LAN netmask has not yet been set in UCI.\"");
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve LAN netmask from UCI.\"]}", token->val);
		return;
	}

	char data[BUFSIZ];
	char* tdata = data;
	size_t datalen = BUFSIZ;
	data[0] = '\0';

	if (strnlen(ipaddr, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"ip\":\"%s\"", ipaddr);
	}
	if (strnlen(netmask, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"netmask\":\"%s\"", netmask);
	}

	if (datalen == BUFSIZ) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve any data from UCI.\"", token->val);
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

	printf("{\"xsrf\":\"%s\",%s", token->val, data + 1);
	if (errlen != BUFSIZ) {
		printf(",\"errors\":[%s]}", errors + 1);
	} else {
		printf("}");
	}

}

