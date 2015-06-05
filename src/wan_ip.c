#include <config.h>
#include "wan_ip.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdbool.h>
#include <stdlib.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"
#include "xsrf.h"

#define PROTO_UCI_PATH "network.wan.proto"
#define IPADDR_UCI_PATH "network.wan.ipaddr"
#define NETMASK_UCI_PATH "network.wan.netmask"
#define GATEWAY_UCI_PATH "network.wan.gateway"

#define MAX_IP_LENGTH 32

#define GET_WAN_COMMAND "ifconfig -a | awk '$1 == \"'`uci get network.wan.ifname`'\" {getline; if ($1 == \"inet\") {raddr = $2; split(raddr, saddr, \":\"); rmask = $4; split(rmask, smask, \":\"); print saddr[2] \" \" smask[2];}}'"
#define GET_GATEWAY_COMMAND "netstat -nr | awk '$1 == \"0.0.0.0\" {print $2;}'"

/*
 * returns true if successful
 * */
bool get_wan_ip4(uint32_t* base, uint32_t* netmask)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char tstr[BUFSIZ];
	ctx = uci_alloc_context();

	strncpy(tstr, PROTO_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, tstr, true)) != UCI_OK
			|| (ptr.flags & UCI_LOOKUP_COMPLETE) == 0) {
		*base = 0;
		*netmask = 0;
		return false;
	} else if (strncmp(ptr.o->v.string, "dhcp", 5) == 0) {
		FILE* output = popen(GET_WAN_COMMAND, "r");
		char* delim = tstr;

		if (output == NULL) {
			*base = 0;
			*netmask = 0;
			pclose(output);
			return false;
		} else if (fgets(tstr, BUFSIZ, output) == NULL) {
			*base = 0;
			*netmask = 0;
			pclose(output);
			return false;
		} else if ((delim = index(tstr, ' ')) == NULL) {
			*base = 0;
			*netmask = 0;
			pclose(output);
			return false;
		} else {
			size_t len = 0;
			if ((len = strnlen(delim, BUFSIZ)) >= BUFSIZ) {
				*base = 0;
				*netmask = 0;
				pclose(output);
				return false;
			} else if (delim[len-1] == '\n') {
				delim[len-1] = '\0';
			}
			*delim = '\0';
			if (inet_pton(AF_INET, tstr, base) == 0) {
				*base = 0;
				*netmask = 0;
				pclose(output);
				return false;
			} else if (inet_pton(AF_INET, delim + 1, netmask) == 0) {
				*base = 0;
				*netmask = 0;
				pclose(output);
				return false;
			}
		}

		pclose(output);
		return true;
	} else if (strncmp(ptr.o->v.string, "static", 7) == 0) {
		strncpy(tstr, IPADDR_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, tstr, true)) != UCI_OK
				|| (ptr.flags & UCI_LOOKUP_COMPLETE) == 0) {
			*base = 0;
			*netmask = 0;
			return false;
		} else if (inet_pton(AF_INET, ptr.o->v.string, base) == 0) {
			*base = 0;
			*netmask = 0;
			return false;
		}

		strncpy(tstr, NETMASK_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, tstr, true)) != UCI_OK
				|| (ptr.flags & UCI_LOOKUP_COMPLETE) == 0) {
			*base = 0;
			*netmask = 0;
			return false;
		} else if (inet_pton(AF_INET, ptr.o->v.string, netmask) == 0) {
			*base = 0;
			*netmask = 0;
			return false;
		}

		return true;
	} else {
		*base = 0;
		*netmask = 0;
		return false;
	}
}

void post_wan_ip(yajl_val top, struct xsrft* token)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* dhcp_yajl_path[] = {"dhcp", (const char*)0};
	const char* ipaddr_yajl_path[] = {"ip", (const char*)0};
	const char* netmask_yajl_path[] = {"netmask", (const char*)0};
	const char* gateway_yajl_path[] = {"gateway", (const char*)0};
	yajl_val dhcp_yajl = yajl_tree_get(top, dhcp_yajl_path, yajl_t_any);
	yajl_val ipaddr_yajl = yajl_tree_get(top, ipaddr_yajl_path, yajl_t_string);
	yajl_val netmask_yajl = yajl_tree_get(top, netmask_yajl_path, yajl_t_string);
	yajl_val gateway_yajl = yajl_tree_get(top, gateway_yajl_path, yajl_t_string);
	bool valid = true;
	bool dhcp = true;
	char ipaddr[BUFSIZ];
	char netmask[BUFSIZ];
	char gateway[BUFSIZ];
	ipaddr[0] = '\0';
	netmask[0] = '\0';
	gateway[0] = '\0';
	if (dhcp_yajl != NULL) {
		if (YAJL_IS_TRUE(dhcp_yajl)) {
			dhcp = true;
		} else if (YAJL_IS_FALSE(dhcp_yajl)) {
			dhcp = false;
		} else {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"DHCP value must be true or false (literally {'dhcp':true} or {'dhcp':false} as per the JSON spec; values such as 1, 'yes', 'true', '1', etc. are not currently accepted).\"]}", token->val);
			return;
		}
	}
	if (ipaddr_yajl != NULL) {
		char* tstr = YAJL_GET_STRING(ipaddr_yajl);
		if (tstr != NULL) {
			int res = 0;
			struct in_addr temp;
			if (tstr[0] == '\0'
					|| strnlen(tstr, MAX_IP_LENGTH + 1) > MAX_IP_LENGTH
					|| (res = inet_pton(AF_INET, tstr, &temp)) == 0) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"A manually-set WAN ip address is currently required to be an IPv4 address sent in dotted-quad notation.\"]}", token->val);
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to parse supplied WAN IPv4 address.\"]}", token->val);
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
					|| (res = inet_pton(AF_INET, tstr, &temp)) == 0) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"A manually-set WAN netmask is currently required to be an IPv4 netmask sent in dotted-quad notation.\"]}", token->val);
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to parse supplied WAN IPv4 netmask.\"]}", token->val);
				return;
			}
			strncpy(netmask, tstr, BUFSIZ);
		}
	}
	if (gateway_yajl != NULL) {
		char* tstr = YAJL_GET_STRING(gateway_yajl);
		if (tstr != NULL) {
			int res = 0;
			struct in_addr temp;
			if (tstr[0] == '\0'
					|| strnlen(tstr, MAX_IP_LENGTH + 1) > MAX_IP_LENGTH
					|| (res = inet_pton(AF_INET, tstr, &temp)) == 0) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"A manually-set WAN gateway address is currently required to be an IPv4 address sent in dotted-quad notation.\"]}", token->val);
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to parse supplied WAN IPv4 gateway address.\"]}", token->val);
				return;
			}
			strncpy(gateway, tstr, BUFSIZ);
		}
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	ctx = uci_alloc_context();

	if (valid && (dhcp_yajl != NULL
				|| strnlen(ipaddr, BUFSIZ) != 0
				|| strnlen(netmask, BUFSIZ) != 0
				|| strnlen(gateway, BUFSIZ) != 0)) {
		if (dhcp_yajl != NULL) {
			snprintf(uci_lookup_str, BUFSIZ, PROTO_UCI_PATH "=%s", dhcp? "dhcp" : "static");
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save WAN DHCP status to UCI.\"]}", token->val);
				return;
			}
		}
		if (strnlen(ipaddr, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, IPADDR_UCI_PATH "=%s", ipaddr);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save WAN IP address to UCI.\"]}", token->val);
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
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save WAN netmask to UCI.\"]}", token->val);
				return;
			}
		}
		if (strnlen(gateway, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, GATEWAY_UCI_PATH "=%s", gateway);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save WAN gateway to UCI.\"]}", token->val);
				return;
			}
		}
		res = uci_commit(ctx, &(ptr.p), true);
	}

	char proto[BUFSIZ];
	proto[0] = '\0';
	ipaddr[0] = '\0';
	netmask[0] = '\0';
	gateway[0] = '\0';

	strncpy(uci_lookup_str, PROTO_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
			&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(proto, ptr.o->v.string, BUFSIZ);
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve WAN DHCP status from UCI.\"]}", token->val);
		return;
	}
	if (strncmp(proto, "dhcp", 5) == 0) {
		dhcp = true;
	} else if (strncmp(proto, "static", 7) == 0) {
		dhcp = false;
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unexpected DHCP alternative is in use for WAN IP address.\"]}", token->val);
		return;
	}
	if (dhcp) {
		FILE* output = popen(GET_WAN_COMMAND, "r");
		char tstr[BUFSIZ];
		char* delim = tstr;
		size_t len = 0;

		if (output == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 adress and netmask for WAN.\"]}", token->val);
			return;
		} else if (fgets(tstr, BUFSIZ, output) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 addres and netmask for WAN.\"]}", token->val);
			pclose(output);
			return;
		} else if ((delim = index(tstr, ' ')) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 address and netmask for WAN.\"]}", token->val);
			pclose(output);
			return;
		} else {
			if ((len = strnlen(delim, BUFSIZ)) >= BUFSIZ) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 address annd netmask for WAN.\"]}", token->val);
				pclose(output);
				return;
			} else if (delim[len-1] == '\n') {
				delim[len-1] = '\0';
			}
			*delim = '\0';
			strncpy(ipaddr, tstr, BUFSIZ);
			strncpy(netmask, delim + 1, BUFSIZ);
		}

		if (pclose(output) == -1 || (output = popen(GET_GATEWAY_COMMAND, "r")) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 gateway adress for WAN.\"]}", token->val);
			return;
		} else if (fgets(gateway, BUFSIZ, output) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 gateway addres for WAN.\"]}", token->val);
			pclose(output);
			return;
		} else if ((len = strnlen(gateway, BUFSIZ)) >= BUFSIZ) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DHCP IPv4 gateway address for WAN.\"]}", token->val);
			pclose(output);
			return;
		} else if (gateway[len-1] == '\n') {
			gateway[len-1] = '\0';
		}
	} else {
		strncpy(uci_lookup_str, IPADDR_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
				&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
			strncpy(ipaddr, ptr.o->v.string, BUFSIZ);
		} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
			/* astpnprintf(&terrors, &errlen, ",\"The WAN IP address has not yet been set in UCI.\""); */
			/* TODO: get from ifconfig if dhcp */
		} else {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve WAN IP address from UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, NETMASK_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
				&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
			strncpy(netmask, ptr.o->v.string, BUFSIZ);
		} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
			/* astpnprintf(&terrors, &errlen, ",\"The WAN netmask has not yet been set in UCI.\""); */
			/* TODO: get from ifconfig if dhcp */
		} else {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve WAN netmask from UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, GATEWAY_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
				&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
			strncpy(gateway, ptr.o->v.string, BUFSIZ);
		} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
			/* astpnprintf(&terrors, &errlen, ",\"The WAN gateway has not yet been set in UCI.\""); */
			/* TODO: get from ifconfig if dhcp */
		} else {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve WAN gateway from UCI.\"]}", token->val);
			return;
		}
	}

	char data[BUFSIZ];
	char* tdata = data;
	size_t datalen = BUFSIZ;
	data[0] = '\0';

	astpnprintf(&tdata, &datalen, ",\"dhcp\":%s", dhcp? "true" : "false");
	if (strnlen(ipaddr, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"ip\":\"%s\"", ipaddr);
	}
	if (strnlen(netmask, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"netmask\":\"%s\"", netmask);
	}
	if (strnlen(gateway, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"gateway\":\"%s\"", gateway);
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
	/* terrors check isn't really necessary */
	if (errlen != BUFSIZ && terrors != errors) {
		printf(",\"errors\":[%s]}", errors + 1);
	} else {
		printf("}");
	}

}

