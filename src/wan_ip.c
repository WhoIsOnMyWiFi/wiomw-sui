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

#define PROTO_UCI_PATH "network.wan.proto"
#define IPADDR_UCI_PATH "network.wan.ipaddr"
#define NETMASK_UCI_PATH "network.wan.netmask"
#define GATEWAY_UCI_PATH "network.wan.gateway"
#define DNS_UCI_PATH "network.wan.dns"

#define MAX_IP_LENGTH 32

#define GET_WAN_COMMAND "ifconfig -a | awk '$1 == \"'`uci get network.wan.ifname`'\" {getline; if ($1 == \"inet\") {raddr = $2; split(raddr, saddr, \":\"); rmask = $4; split(rmask, smask, \":\"); print saddr[2] \" \" smask[2];}}'"
#define GET_GATEWAY_COMMAND "netstat -nr | awk '$1 == \"0.0.0.0\" {print $2;}'"
#define GET_DNS_COMMAND "cat /var/resolv.conf.auto | awk '$1 == \"nameserver\" {print $2;}'"

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
	unsigned int dns_count = 0;
	ipaddr[0] = '\0';
	netmask[0] = '\0';
	gateway[0] = '\0';
	dns[0] = '\0';
	/* TODO: be more forgiving about dhcp:1 and dhcp:"yes" and whatnot? */
	if (dhcp_yajl == NULL) {
		if (YAJL_IS_TRUE(dhcp_yajl)) {
			dhcp = true;
		} else if (YAJL_IS_FALSE(dhcp_yajl)) {
			dhcp = false;
		} else {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"DHCP value must be true or false (literally {\"dhcp\":true} or {\"dhcp\":false} as per the JSON spec; values such as 1, \"yes\", \"true\", \"1\", etc. are not currently accepted).\"]}");
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
				printf("{\"errors\":[\"A manually-set WAN ip address is currently required to be an IPv4 address sent in dotted-quad notation.\"]}");
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to parse supplied WAN IPv4 address.\"]}");
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
				printf("{\"errors\":[\"A manually-set WAN netmask is currently required to be an IPv4 netmask sent in dotted-quad notation.\"]}");
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to parse supplied WAN IPv4 netmask.\"]}");
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
				printf("{\"errors\":[\"A manually-set WAN gateway address is currently required to be an IPv4 address sent in dotted-quad notation.\"]}");
				return;
			} else if (res != 1) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to parse supplied WAN IPv4 gateway address.\"]}");
				return;
			}
			strncpy(gateway, tstr, BUFSIZ);
		}
	}
	if (dns_yajl != NULL) {
		if (dns_yajl->u.array.len > 0) {
			int i;
			char* tdns = dns;
			size_t dnslen = BUFSIZ;
			for (i = 0; i < dns_yajl->u.array.len; i++) {
				char* tstr = YAJL_GET_STRING(dns_yajl->u.array.values[i]);
				int res = 0;
				struct in_addr temp;
				if (tstr[0] == '\0'
						|| strnlen(tstr, MAX_IP_LENGTH + 1) > MAX_IP_LENGTH
						|| (res = inet_pton(AF_INET, tstr, &temp)) == 0) {
					printf("Status: 422 Unprocessable Entity\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"A manually-set WAN DNS address is currently required to be an IPv4 address sent in dotted-quad notation.\"]}");
					return;
				} else if (res != 1) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to parse a supplied WAN IPv4 DNS address.\"]}");
					return;
				}
				astpnprintf(&tdns, &dnslen, "%s", tstr);
				dns_count++;
				if (dnslen > 0) {
					dnslen--;
					tdns++;
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
				|| dns_yajl != NULL)) {
		if (dhcp_yajl != NULL) {
			snprintf(uci_lookup_str, BUFSIZ, PROTO_UCI_PATH "=%s", dhcp? "dhcp" : "static");
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_set(ctx, &ptr)) != UCI_OK
					|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to save WAN DHCP status to UCI.\"]}");
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
				printf("{\"errors\":[\"Unable to save WAN IP address to UCI.\"]}");
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
				printf("{\"errors\":[\"Unable to save WAN netmask to UCI.\"]}");
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
				printf("{\"errors\":[\"Unable to save WAN gateway to UCI.\"]}");
				return;
			}
		}
		if (dns_yajl != NULL) {
			char* tdns = dns;
			unsigned int i = 0;
			strncpy(uci_lookup_str, DNS_UCI_PATH, BUFSIZ);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| ((ptr.flags & UCI_LOOKUP_COMPLETE) == 0
						&& ((res = uci_delete(ctx, &ptr)) != UCI_OK
							|| (res = uci_save(ctx, ptr.p)) != UCI_OK))) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to change old WAN DNS servers in UCI.\"]}");
				return;
			}
			for (i = 0; i < dns_count; i++) {
				snprintf(uci_lookup_str, BUFSIZ, DNS_UCI_PATH "=%s", tdns);
				if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
						|| (res = uci_add_list(ctx, &ptr)) != UCI_OK) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"errors\":[\"Unable to add WAN DNS server to UCI.\"]}");
					return;
				}
				tdns += strlen(tdns) + 1;
			}
			if (dns_count > 0 && (res = uci_save(ctx, ptr.p)) != UCI_OK) {
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
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
			&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		strncpy(proto, ptr.o->v.string, BUFSIZ);
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve WAN DHCP status from UCI.\"]}");
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
	if (dhcp) {
		FILE* output = popen(GET_WAN_COMMAND, "r");
		char tstr[BUFSIZ];
		char* delim = tstr;
		size_t len = 0;

		if (output == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DHCP IPv4 adress and netmask for WAN.\"]}");
			return;
		} else if (fgets(tstr, BUFSIZ, output) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DHCP IPv4 addres and netmask for WAN.\"]}");
			pclose(output);
			return;
		} else if ((delim = index(tstr, ' ')) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DHCP IPv4 address and netmask for WAN.\"]}");
			pclose(output);
			return;
		} else {
			if ((len = strnlen(delim, BUFSIZ)) >= BUFSIZ) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to get DHCP IPv4 address annd netmask for WAN.\"]}");
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
			printf("{\"errors\":[\"Unable to get DHCP IPv4 gateway adress for WAN.\"]}");
			return;
		} else if (fgets(gateway, BUFSIZ, output) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DHCP IPv4 gateway addres for WAN.\"]}");
			pclose(output);
			return;
		} else if ((len = strnlen(gateway, BUFSIZ)) >= BUFSIZ) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DHCP IPv4 gateway address for WAN.\"]}");
			pclose(output);
			return;
		} else if (gateway[len-1] == '\n') {
			gateway[len-1] = '\0';
		}

		char* tdns = dns;
		size_t dnslen = BUFSIZ;
		if (pclose(output) == -1 || (output = popen(GET_DNS_COMMAND, "r")) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DNS addresses for WAN.\"]}");
			return;
		}
		while (fgets(tstr, BUFSIZ, output) != NULL) {
			if ((len = strnlen(tstr, BUFSIZ)) >= BUFSIZ) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to get DNS address for WAN.\"]}");
				pclose(output);
				return;
			} else if (tstr[len-1] == '\n') {
				tstr[len-1] = '\0';
			}
			astpnprintf(&tdns, &dnslen, ",\"%s\"", tstr);
		}
		if (!feof(output)) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to get DNS adresses for WAN.\"]}");
			pclose(output);
			return;
		}
		pclose(output);

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
			printf("{\"errors\":[\"Unable to retrieve WAN IP address from UCI.\"]}");
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
			printf("{\"errors\":[\"Unable to retrieve WAN netmask from UCI.\"]}");
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
			printf("{\"errors\":[\"Unable to retrieve WAN gateway from UCI.\"]}");
			return;
		}
		strncpy(uci_lookup_str, DNS_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
				&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
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
		astpnprintf(&tdata, &datalen, ",\"dns\":[%s]", dns + 1);
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
	/* terrors check isn't really necessary */
	if (errlen != BUFSIZ && terrors != errors) {
		printf(",\"errors\":[%s]}", errors + 1);
	} else {
		printf("}");
	}

}

