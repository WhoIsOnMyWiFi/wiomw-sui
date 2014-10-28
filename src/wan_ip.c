#include <config.h>
#include "wan_ip.h"

#include <string.h>
#include <stdio.h>
#include <uci.h>
#include <stdlib.h>
#include <syslog.h>
#include <yajl/yajl_tree.h>

#include "string_helpers.h"

#define PROTO_UCI_PATH "network.wan.proto"
#define IPADDR_UCI_PATH "network.wan.ipaddr"
#define NETMASK_UCI_PATH "network.wan.netmask"
#define GATEWAY_UCI_PATH "network.wan.gateway"
#define DNS_UCI_PATH "network.wan.dns"

void post_wan_ip(yajl_val top)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* dhcp_yajl_path[] = {"dhcp", (const char*)0};
	const char* ipaddr_yajl_path[] = {"ip", (const char*)0};
	const char* netmask_yajl_path[] = {"netmask", (const char*)0};
	const char* gateway_yajl_path[] = {"gateway", (const char*)0};
	const char* dns_yajl_path[] = {"dns", (const char*)0};
	yajl_val dhcp_yajl = yajl_tree_get(top, dhcp_yajl_path, yajl_t_any);
	yajl_val ipaddr_yajl = yajl_tree_get(top, ipaddr_yajl_path, yajl_t_string);
	yajl_val netmask_yajl = yajl_tree_get(top, netmask_yajl_path, yajl_t_string);
	yajl_val gateway_yajl = yajl_tree_get(top, gateway_yajl_path, yajl_t_string);
	yajl_val dns_yajl = yajl_tree_get(top, dns_yajl_path, yajl_t_array);
	bool valid = true;
	bool dhcp = true;
	char ipaddr[BUFSIZ];
	char netmask[BUFSIZ];
	char gateway[BUFSIZ];
	char dns[BUFSIZ];
	ipaddr[0] = '\0';
	netmask[0] = '\0';
	gateway[0] = '\0';
	dns[0] = '\0';
	/* TODO: be more forgiving about dhcp:1 and dhcp:"yes" and whatnot? */
	if (dhcp_yajl == NULL || !YAJL_IS_TRUE(dhcp_yajl)) {
		dhcp = false;
		if (ipaddr_yajl != NULL) {
			/* TODO: validate */
			strncpy(ipaddr, YAJL_GET_STRING(ipaddr_yajl), BUFSIZ);
		}
		if (netmask_yajl != NULL) {
			/* TODO: validate */
			strncpy(netmask, YAJL_GET_STRING(netmask_yajl), BUFSIZ);
		}
		if (gateway_yajl != NULL) {
			/* TODO: validate */
			strncpy(gateway, YAJL_GET_STRING(gateway_yajl), BUFSIZ);
		}
		if (dns_yajl != NULL) {
			if (dns_yajl->u.array.len > 0) {
				int i;
				char* tdns = dns;
				size_t dnslen = BUFSIZ;
				/* TODO: validate */
				astpnprintf(&tdns, &dnslen, "%s", YAJL_GET_STRING(dns_yajl->u.array.values[0]));
				for (i = 1; i < dns_yajl->u.array.len; i++) {
					astpnprintf(&tdns, &dnslen, " %s", YAJL_GET_STRING(dns_yajl->u.array.values[i]));
				}
			}
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
				|| strnlen(gateway, BUFSIZ) != 0
				|| strnlen(dns, BUFSIZ) != 0)) {
		if (dhcp_yajl != NULL) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", PROTO_UCI_PATH, dhcp? "dhcp" : "static");
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WAN DHCP status to UCI.\"]}");
				return;
			}
		}
		if (strnlen(ipaddr, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", IPADDR_UCI_PATH, ipaddr);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WAN IP address to UCI.\"]}");
				return;
			}
		}
		if (strnlen(netmask, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", NETMASK_UCI_PATH, netmask);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WAN netmask to UCI.\"]}");
				return;
			}
		}
		if (strnlen(gateway, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", GATEWAY_UCI_PATH, gateway);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WAN gateway to UCI.\"]}");
				return;
			}
		}
		if (strnlen(dns, BUFSIZ) != 0) {
			snprintf(uci_lookup_str, BUFSIZ, "%s=%s", DNS_UCI_PATH, dns);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p) != UCI_OK)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WAN DNS servers to UCI.\"]}");
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
	dns[0] = '\0';

	strncpy(uci_lookup_str, PROTO_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(proto, ptr.o->v.string, BUFSIZ);
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve WAN IP address from UCI.\"]}");
		return;
	}
	if (strncmp(proto, "dhcp", 5) == 0) {
		dhcp = true;
	} else if (strncmp(proto, "static", 7) == 0) {
		dhcp = false;
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unexpected DHCP alternative is in use for WAN IP address.\"]}");
		return;
	}
	strncpy(uci_lookup_str, IPADDR_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(ipaddr, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The WAN IP address has not yet been set in UCI.\""); */
		/* TODO: get from ifconfig if dhcp */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve WAN IP address from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, NETMASK_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(netmask, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The WAN netmask has not yet been set in UCI.\""); */
		/* TODO: get from ifconfig if dhcp */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve WAN netmask from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, GATEWAY_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(gateway, ptr.o->v.string, BUFSIZ);
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The WAN gateway has not yet been set in UCI.\""); */
		/* TODO: get from ifconfig if dhcp */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve WAN gateway from UCI.\"]}");
		return;
	}
	strncpy(uci_lookup_str, DNS_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK && (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		int i;
		char* tdns = dns;
		size_t dnslen = BUFSIZ;
		struct uci_element* elm;
		uci_foreach_element(&(ptr.o->v.list), elm) {
			astpnprintf(&tdns, &dnslen, ",\"%s\"", elm->name);
		}
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The WAN gateway has not yet been set in UCI.\""); */
		/* TODO: get from ifconfig if dhcp */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve WAN DNS entries from UCI.\"]}");
		return;
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
	if (strnlen(dns, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"dns\":[%s]", dns);
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

