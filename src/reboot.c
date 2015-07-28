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
#include "reboot.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "wan_ip.h"
#include "lan_ip.h"
#include "range_check.h"

#define REBOOT_COMMAND "sleep 3 && reboot &"

void post_reboot()
{
	uint32_t lan_ip = 0;
	uint32_t lan_netmask = 0;

	if (get_lan_ip4(&lan_ip, &lan_netmask) && lan_ip != 0 && lan_netmask != 0) {
		uint32_t wan_ip = 0;
		uint32_t wan_netmask = 0;

		if (get_wan_ip4(&wan_ip, &wan_netmask)) {
			if (ip4_check_range(lan_ip, lan_netmask, wan_ip, wan_netmask)) {
				if (ip4_check_range(wan_ip, wan_netmask, htonl(0xC0A80000), htonl(0xFFFF0000))) {
					set_lan_ip4("172.16.0.1", "255.255.255.0");
				} else {
					set_lan_ip4("192.168.0.1", "255.255.255.0");
				}
			}
		}
	}
	if (system(REBOOT_COMMAND) == -1) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"rebooting\":false,\"errors\":[\"Unable to reboot system.\"]}");
		return;
	}
	printf("Status: 200 OK\n");
	printf("Content-type: application/json\n\n");
	printf("{\"rebooting\":true}");
}

