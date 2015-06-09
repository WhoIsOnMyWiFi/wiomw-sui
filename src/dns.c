#include <config.h>
#include "dns.h"

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

#define DNS_UCI_PATH "network.wan.dns"
#define LAN_IP_UCI_PATH "network.lan.ipaddr"
#define INTERCEPT_UCI_PATH "firewall.dns_intercept"
#define INTERCEPT_UCI_VALUE INTERCEPT_UCI_PATH "=redirect"
#define INTERCEPT_NAME_UCI_VALUE INTERCEPT_UCI_PATH ".name=DNS Interception"
#define INTERCEPT_SRC_UCI_VALUE INTERCEPT_UCI_PATH ".src=lan"
#define INTERCEPT_PROTO_UCI_VALUE INTERCEPT_UCI_PATH ".proto=udp"
#define INTERCEPT_SPORT_UCI_VALUE INTERCEPT_UCI_PATH ".src_dport=53"
#define INTERCEPT_DPORT_UCI_VALUE INTERCEPT_UCI_PATH ".dest_port=53"
#define INTERCEPT_SRC_IP_UCI_PREFIX INTERCEPT_UCI_PATH ".src_dip=!"
#define INTERCEPT_DEST_IP_UCI_PREFIX INTERCEPT_UCI_PATH ".dest_ip="

#define OPENDNS_ENHANCED_DNS_1 "208.67.222.222"
#define OPENDNS_ENHANCED_DNS_2 "208.67.220.220"
#define OPENDNS_FAMILY_SHIELD_DNS_1 "208.67.222.123"
#define OPENDNS_FAMILY_SHIELD_DNS_2 "208.67.220.123"
#define GOOGLE_DNS_1 "8.8.8.8"
#define GOOGLE_DNS_2 "8.8.4.4"

#define MAX_IP_LENGTH 32

#define GET_DNS_COMMAND "cat /var/resolv.conf.auto | awk '$1 == \"nameserver\" {print $2;}'"

void post_dns(yajl_val top, struct xsrft* token)
{
	char errors[BUFSIZ];
	char* terrors = errors;
	size_t errlen = BUFSIZ;
	errors[0] = '\0';

	const char* opendns_yajl_path[] = {"opendns_enhanced_dns", (const char*)0};
	const char* opendns_family_shield_yajl_path[] = {"opendns_family_shield_dns", (const char*)0};
	const char* google_yajl_path[] = {"google_dns", (const char*)0};
	const char* interception_yajl_path[] = {"dns_interception", (const char*)0};
	const char* custom_nameservers_yajl_path[] = {"custom_nameservers", (const char*)0};
	yajl_val opendns_yajl = yajl_tree_get(top, opendns_yajl_path, yajl_t_any);
	yajl_val opendns_family_shield_yajl = yajl_tree_get(top, opendns_family_shield_yajl_path, yajl_t_any);
	yajl_val google_yajl = yajl_tree_get(top, google_yajl_path, yajl_t_any);
	yajl_val interception_yajl = yajl_tree_get(top, interception_yajl_path, yajl_t_any);
	yajl_val custom_nameservers_yajl = yajl_tree_get(top, custom_nameservers_yajl_path, yajl_t_array);
	int opendns = 0;
	int opendns_family_shield = 0;
	int google = 0;
	int interception = 0;
	char dns[BUFSIZ];
	unsigned int dns_count = 0;
	char* tdns = dns;
	size_t dnslen = BUFSIZ;
	dns[0] = '\0';
	if (custom_nameservers_yajl != NULL) {
		if (custom_nameservers_yajl->u.array.len > 0) {
			int i;
			for (i = 0; i < custom_nameservers_yajl->u.array.len; i++) {
				char* tstr = YAJL_GET_STRING(custom_nameservers_yajl->u.array.values[i]);
				int res = 0;
				struct in_addr temp;
				if (tstr[0] == '\0'
						|| strnlen(tstr, MAX_IP_LENGTH + 1) > MAX_IP_LENGTH
						|| (res = inet_pton(AF_INET, tstr, &temp)) == 0) {
					printf("Status: 422 Unprocessable Entity\n");
					printf("Content-type: application/json\n\n");
					printf("{\"xsrf\":\"%s\",\"errors\":[\"A custom nameserver is currently required to be an IPv4 address sent in dotted-quad notation.\"]}", token->val);
					return;
				} else if (res != 1) {
					printf("Status: 500 Internal Server Error\n");
					printf("Content-type: application/json\n\n");
					printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to parse a supplied custom nameserver.\"]}", token->val);
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
	if (opendns_yajl != NULL) {
		if (YAJL_IS_TRUE(opendns_yajl)) {
			opendns = 1;
			astpnprintf(&tdns, &dnslen, OPENDNS_ENHANCED_DNS_1);
			dns_count++;
			if (dnslen > 0) {
				dnslen--;
				tdns++;
			}
			astpnprintf(&tdns, &dnslen, OPENDNS_ENHANCED_DNS_2);
			dns_count++;
			if (dnslen > 0) {
				dnslen--;
				tdns++;
			}
		} else if (YAJL_IS_FALSE(opendns_yajl)) {
			opendns = -1;
		} else {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"OpenDNS Enhanced DNS value must be true or false (literally {'opendns_enhanced_dns':true} or {'opendns_enhanced_dns':false} as per the JSON spec; values such as 1, 'yes', 'true', '1', etc. are not currently accepted).\"]}", token->val);
			return;
		}
	}
	if (opendns_family_shield_yajl != NULL) {
		if (opendns != 0) {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Only one pre-configured DNS option is allowed. For custom DNS configurations, please use 'custom_nameservers'.\"]}", token->val);
			return;
		} else if (YAJL_IS_TRUE(opendns_family_shield_yajl)) {
			opendns_family_shield = 1;
			astpnprintf(&tdns, &dnslen, OPENDNS_FAMILY_SHIELD_DNS_1);
			dns_count++;
			if (dnslen > 0) {
				dnslen--;
				tdns++;
			}
			astpnprintf(&tdns, &dnslen, OPENDNS_FAMILY_SHIELD_DNS_2);
			dns_count++;
			if (dnslen > 0) {
				dnslen--;
				tdns++;
			}
		} else if (YAJL_IS_FALSE(opendns_family_shield_yajl)) {
			opendns_family_shield = -1;
		} else {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"OpenDNS Family Shield DNS value must be true or false (literally {'opendns_family_shield_dns':true} or {'opendns_family_shield_dns':false} as per the JSON spec; values such as 1, 'yes', 'true', '1', etc. are not currently accepted).\"]}", token->val);
			return;
		}
	}
	if (google_yajl != NULL) {
		if (opendns != 0 || opendns_family_shield != 0) {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Only one pre-configured DNS option is allowed. For custom DNS configurations, please use 'custom_nameservers'.\"]}", token->val);
			return;
		} else if (YAJL_IS_TRUE(google_yajl)) {
			google = 1;
			astpnprintf(&tdns, &dnslen, GOOGLE_DNS_1);
			dns_count++;
			if (dnslen > 0) {
				dnslen--;
				tdns++;
			}
			astpnprintf(&tdns, &dnslen, GOOGLE_DNS_2);
			dns_count++;
			if (dnslen > 0) {
				dnslen--;
				tdns++;
			}
		} else if (YAJL_IS_FALSE(google_yajl)) {
			google = -1;
		} else {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Google DNS value must be true or false (literally {'google_dns':true} or {'google_dns':false} as per the JSON spec; values such as 1, 'yes', 'true', '1', etc. are not currently accepted).\"]}", token->val);
			return;
		}
	}
	if (interception_yajl != NULL) {
		if (YAJL_IS_TRUE(interception_yajl)) {
			interception = 1;
		} else if (YAJL_IS_FALSE(interception_yajl)) {
			interception = -1;
		} else {
			printf("Status: 422 Unprocessable Entity\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"DNS interception value must be true or false (literally {'dns_interception':true} or {'dns_interception':false} as per the JSON spec; values such as 1, 'yes', 'true', '1', etc. are not currently accepted).\"]}", token->val);
			return;
		}
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	int i = 0;
	tdns = dns;
	ctx = uci_alloc_context();

	if (custom_nameservers_yajl != NULL || opendns != 0 || opendns_family_shield != 0 || google != 0) {
		strncpy(uci_lookup_str, DNS_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0
					&& ((res = uci_delete(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p)) != UCI_OK))) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to change old DNS servers in UCI.\"]}", token->val);
			return;
		}

		for (i = 0; i < dns_count; i++) {
			snprintf(uci_lookup_str, BUFSIZ, DNS_UCI_PATH "=%s", tdns);
			if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
					|| (res = uci_add_list(ctx, &ptr)) != UCI_OK) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to add DNS server to UCI.\"]}", token->val);
				return;
			}
			tdns += strlen(tdns) + 1;
		}
		if (dns_count > 0 && (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS servers to UCI.\"]}", token->val);
			return;
		}

		if ((res = uci_commit(ctx, &(ptr.p), false)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS servers to UCI.\"]}", token->val);
			return;
		}
	}

	if (interception == -1) {
		strncpy(uci_lookup_str, INTERCEPT_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0
					&& ((res = uci_delete(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p)) != UCI_OK))) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to change DNS interception setting in UCI.\"]}", token->val);
			return;
		}

		if ((res = uci_commit(ctx, &(ptr.p), false)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to disable DNS interception setting in UCI.\"]}", token->val);
			return;
		}
	} else if (interception == 1) {
		char lan_ip[BUFSIZ];
		lan_ip[0] = '\0';

		strncpy(uci_lookup_str, LAN_IP_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
				&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
			strncpy(lan_ip, ptr.o->v.string, BUFSIZ);
		} else {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve LAN IP address from UCI (needed for DNS interception setting).\"]}", token->val);
			return;
		}

		strncpy(uci_lookup_str, INTERCEPT_UCI_PATH, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0
					&& ((res = uci_delete(ctx, &ptr)) != UCI_OK
						|| (res = uci_save(ctx, ptr.p)) != UCI_OK))) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to access DNS interception setting in UCI.\"]}", token->val);
			return;
		}

		strncpy(uci_lookup_str, INTERCEPT_UCI_VALUE, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, INTERCEPT_NAME_UCI_VALUE, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, INTERCEPT_SRC_UCI_VALUE, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, INTERCEPT_PROTO_UCI_VALUE, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, INTERCEPT_SPORT_UCI_VALUE, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		strncpy(uci_lookup_str, INTERCEPT_DPORT_UCI_VALUE, BUFSIZ);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		snprintf(uci_lookup_str, BUFSIZ, INTERCEPT_SRC_IP_UCI_PREFIX "%s", lan_ip);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}
		snprintf(uci_lookup_str, BUFSIZ, INTERCEPT_DEST_IP_UCI_PREFIX "%s", lan_ip);
		if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK
				|| (res = uci_set(ctx, &ptr)) != UCI_OK
				|| (res = uci_save(ctx, ptr.p)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to save DNS interception setting to UCI.\"]}", token->val);
			return;
		}

		if ((res = uci_commit(ctx, &(ptr.p), false)) != UCI_OK) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to enable DNS interception setting to UCI.\"]}", token->val);
			return;
		}
	}

	FILE* output = NULL;
	char active_dns[BUFSIZ];
	char tstr[BUFSIZ];
	char* atdns = active_dns;
	size_t adnslen = BUFSIZ;
	size_t len = 0;
	active_dns[0] = '\0';
	opendns = false;
	opendns_family_shield = false;
	google = false;
	interception = false;
	dns[0] = '\0';

	if ((output = popen(GET_DNS_COMMAND, "r")) == NULL) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get current nameservers.\"]}", token->val);
		return;
	}
	while (fgets(tstr, BUFSIZ, output) != NULL) {
		if ((len = strnlen(tstr, BUFSIZ)) >= BUFSIZ) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get current nameservers.\"]}", token->val);
			pclose(output);
			return;
		} else if (tstr[len-1] == '\n') {
			tstr[len-1] = '\0';
		}
		astpnprintf(&atdns, &adnslen, ",\"%s\"", tstr);
	}
	if (!feof(output)) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get current nameservers.\"]}", token->val);
		pclose(output);
		return;
	}
	pclose(output);

	strncpy(uci_lookup_str, DNS_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
			&& (ptr.flags & UCI_LOOKUP_COMPLETE)) {
		size_t dnslen = BUFSIZ;
		struct uci_element* elm;
		tdns = dns;
		uci_foreach_element(&(ptr.o->v.list), elm) {
			if (strcmp(elm->name, OPENDNS_ENHANCED_DNS_1) == 0
					|| strcmp(elm->name, OPENDNS_ENHANCED_DNS_2) == 0) {
				opendns = true;
			} else if (strcmp(elm->name, OPENDNS_FAMILY_SHIELD_DNS_1) == 0
					|| strcmp(elm->name, OPENDNS_FAMILY_SHIELD_DNS_2) == 0) {
				opendns_family_shield = true;
			} else if (strcmp(elm->name, GOOGLE_DNS_1) == 0
					|| strcmp(elm->name, GOOGLE_DNS_2) == 0) {
				google = true;
			} else {
				astpnprintf(&tdns, &dnslen, ",\"%s\"", elm->name);
			}
		}
	} else if (res == UCI_ERR_NOTFOUND || (ptr.flags & UCI_LOOKUP_DONE)) {
		/* astpnprintf(&terrors, &errlen, ",\"The WAN gateway has not yet been set in UCI.\""); */
		/* TODO: get from ifconfig if dhcp */
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to retrieve nameservers from UCI.\"]}", token->val);
		return;
	}

	strncpy(uci_lookup_str, INTERCEPT_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"xsrf\":\"%s\",\"errors\":[\"Unable to get DNS interception setting from UCI.\"]}", token->val);
		return;
	} else if (ptr.flags & UCI_LOOKUP_COMPLETE) {
		interception = true;
	}

	char data[BUFSIZ];
	char* tdata = data;
	size_t datalen = BUFSIZ;
	data[0] = '\0';

	astpnprintf(&tdata, &datalen, ",\"current_nameservers\":[%s]", active_dns + 1);
	if (opendns) {
		astpnprintf(&tdata, &datalen, ",\"opendns_enhanced_dns\":true");
	} else {
		astpnprintf(&tdata, &datalen, ",\"opendns_enhanced_dns\":false");
	}
	if (opendns_family_shield) {
		astpnprintf(&tdata, &datalen, ",\"opendns_family_shield_dns\":true");
	} else {
		astpnprintf(&tdata, &datalen, ",\"opendns_family_shield_dns\":false");
	}
	if (google) {
		astpnprintf(&tdata, &datalen, ",\"google_dns\":true");
	} else {
		astpnprintf(&tdata, &datalen, ",\"google_dns\":false");
	}
	if (strnlen(dns, BUFSIZ) != 0) {
		astpnprintf(&tdata, &datalen, ",\"custom_nameservers\":[%s]", dns + 1);
	}
	if (interception) {
		astpnprintf(&tdata, &datalen, ",\"dns_interception\":true");
	} else {
		astpnprintf(&tdata, &datalen, ",\"dns_interception\":false");
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

