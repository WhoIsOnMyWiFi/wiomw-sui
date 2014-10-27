#include <config.h>
#include "mac.h"

#include <stdio.h>

#define GET_MAC_COMMAND "ifconfig -a | grep `uci get network.wan.ifname` | awk '{print $5;}'"

void get_mac()
{
	char mac[18];
	FILE* output = popen(GET_MAC_COMMAND, "r");
	if (output == NULL) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("\"errors\":[\"Unable to retrieve MAC address.\"]}");
		return;
	}
	if (fread(mac, 1, 18, output) != 18) {
		pclose(output);
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve entire MAC address.\"]}");
		return;
	}
	pclose(output);
	if (mac[17] == '\n') {
		mac[17] = '\0';
	} else if (mac[17] != '\0') {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Retrieved invalid MAC address.\"]}");
		return;
	}
	printf("Status: 200 OK\n");
	printf("Content-type: application/json\n\n");
	printf("{\"mac\":\"%s\"}", mac);
}

