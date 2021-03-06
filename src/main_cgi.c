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

#ifndef HAVE_FCGI_STDIO_H
#define HAVE_FCGI_STDIO_H 0
#else
#if HAVE_FCGI_STDIO_H
#include <fcgi_stdio.h>
#endif
#endif

#include <stdio.h>
#include <ctype.h>
#include <syslog.h>
#include <string.h>
#include <stdlib.h>
#include <yajl/yajl_tree.h>

#include "check.h"
#include "password.h"
#include "wifi.h"
#include "wiomw.h"
#include "mac.h"
#include "reboot.h"
#include "wan_ip.h"
#include "lan_ip.h"
#include "update.h"
#include "version.h"
#include "xsrf.h"
#include "dns.h"

#define JSON_ERROR_BUFFER_LEN 1024

int main()
{
#if HAVE_FCGI_STDIO_H
	while (FCGI_Accept() >= 0) {
#endif
		const char* method = getenv("REQUEST_METHOD");
		const char* query = getenv("QUERY_STRING");
		if (method == NULL) {
			printf("Status: 400 Bad Request\n");
			printf("Allow: GET, POST, HEAD\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to determine HTTP method.\"]}");
		} else if (strcmp(method, "POST") == 0) {
			const unsigned long int length = strtoul(getenv("CONTENT_LENGTH"), NULL, 0);
			/* TODO: check content length sanity */
			char* data = (char*)malloc(length);
			char yajl_err_buf[JSON_ERROR_BUFFER_LEN];
			yajl_val top = NULL;
			size_t bytes = fread(data, 1, length, stdin);
			if (bytes != length && !feof(stdin)) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Error while reading POST data.\"]}");
			} else if (((top = yajl_tree_parse(data, yajl_err_buf, JSON_ERROR_BUFFER_LEN)) == NULL) || YAJL_IS_ARRAY(top)) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to parse data as JSON object.\"]}");
			} else if (query == NULL) {
				printf("Status: 400 Bad Request\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Query required in URL.\"]}");
			} else if (strcmp(query, "wiomw") == 0) {
				post_wiomw(top);
			} else if (strcmp(query, "password") == 0) {
				post_password(top);
			} else if (strcmp(query, "version") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_version(top, &token);
				}
			} else if (strcmp(query, "wifi") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_wifi(top, &token);
				}
			} else if (strcmp(query, "reboot") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_reboot();
				}
			} else if (strcmp(query, "wan_ip") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_wan_ip(top, &token);
				}
			} else if (strcmp(query, "dns") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_dns(top, &token);
				}
			} else if (strcmp(query, "lan_ip") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_lan_ip(top, &token);
				}
			} else if (strcmp(query, "update.log") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_update_log(top, &token);
				}
			} else if (strcmp(query, "update") == 0) {
				struct xsrft token;
				if (valid_creds(top, &token)) {
					post_update(top, &token);
				}
			} else {
				printf("Status: 400 Bad Request\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Invalid query in URL.\"]}");
			}
			if (top != NULL) {
				yajl_tree_free(top);
			}
			free(data);
		} else if (strcmp(method, "GET") == 0 || strcmp(method, "HEAD") == 0) {
			if (query == NULL) {
				printf("Status: 400 Bad Request\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Query required in URL.\"]}");
			} else if (strcmp(query, "check") == 0) {
				get_check();
			} else if (strcmp(query, "mac") == 0) {
				get_mac();
			} else if (strcmp(query, "check_reboot") == 0) {
				get_check_reboot();
			} else {
				printf("Status: 400 Bad Request\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Invalid query in URL.\"]}");
			}
		} else {
			printf("Status: 405 Method Not Allowed\n");
			printf("Allow: GET, POST, HEAD\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Received HTTP method other than GET, POST, or HEAD.\"]}");
		}

#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

