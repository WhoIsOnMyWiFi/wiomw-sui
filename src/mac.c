/**
 * Copyright 2014, 2015 Who Is On My WiFi.
 *
 * This file is part of Who Is On My WiFi Linux.
 *
 * Who Is On My WiFi Linux is free software: you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * Who Is On My WiFi Linux is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
 * Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
 *
 * More information about Who Is On My WiFi Linux can be found at
 * <http://www.whoisonmywifi.com/>.
 */

#include <config.h>
#include "mac.h"

#include <stdio.h>

#define GET_MAC_COMMAND "ifconfig -a | awk '$1 == \"'`uci get network.wan.ifname`'\" {print $5;}'"

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

