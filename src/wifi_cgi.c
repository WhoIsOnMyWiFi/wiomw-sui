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

#include "wifi_uci.h"
#include "login_check.h"

#define JSON_ERROR_BUFFER_LEN 1024

int main()
{
#if HAVE_FCGI_STDIO_H
	while (FCGI_Accept() >= 0) {
#endif
		char* method = getenv("REQUEST_METHOD");
		if (method == NULL) {
			printf("Status: 400 Bad Request\n");
			printf("Allow: POST\n");
			printf("{\"errors\":[\"Unable to determine HTTP method.\"]}");
		} else if (strcmp(method, "POST") == 0) {
			unsigned long int length = strtoul(getenv("CONTENT_LENGTH"), NULL, 0);
			char* data = (char*)malloc(length);
			char yajl_err_buf[JSON_ERROR_BUFFER_LEN];
			yajl_val top;
			size_t bytes = fread(data, 1, length, stdin);
			const char* password_path[] = {"password", (const char*)0};
			yajl_val yajl_password;

			if (bytes != length && !feof(stdin)) {
				printf("Status: 500 Internal Server Error\n");
				printf("{\"errors\":[\"Error while reading POST data.\"]}");
				free(data);
			} else if (((top = yajl_tree_parse(data, yajl_err_buf, JSON_ERROR_BUFFER_LEN)) == NULL) || YAJL_IS_ARRAY(top)) {
				printf("Status: 422 Unprocessable Entity\n");
				printf("{\"errors\":[\"Unable to parse data as JSON object.\"]}");
				yajl_tree_free(top);
				free(data);
			} else if ((yajl_password = yajl_tree_get(top, password_path, yajl_t_string)) == NULL) {
				printf("Status: 403 Forbidden\n");
				printf("{\"errors\":[\"No password supplied in JSON object.\"]}");
				yajl_tree_free(top);
				free(data);
			} else if (!login_check(YAJL_GET_STRING(yajl_password))) {
				printf("Status: 403 Forbidden\n");
				printf("{\"errors\":[\"Bad password supplied in JSON object.\"]}");
				yajl_tree_free(top);
				free(data);
				/* TODO sleep in order to rate limit */
			} else {
				char* error = NULL;
				const char* ssid_path[] = {"ssid", (const char*)0};
				const char* psk_path[] = {"psk", (const char*)0};
				yajl_val yajl_ssid = yajl_tree_get(top, ssid_path, yajl_t_string);
				yajl_val yajl_psk = yajl_tree_get(top, psk_path, yajl_t_string);

				if (yajl_ssid != NULL && yajl_psk != NULL) {
					char* ssid = YAJL_GET_STRING(yajl_ssid);
					char* psk = YAJL_GET_STRING(yajl_psk);

					/* TODO de-HTML-ify */
					/* TODO validate ssid */
					/* TODO validate psk */

					if (set_wifi_vals(ssid, psk) != 0) {
						printf("Status: 500 Internal Server Error\n");
						error = "\"Unable to save SSID and PSK.\"";
					}
				} else if (yajl_ssid == NULL) {
					char* psk = YAJL_GET_STRING(yajl_psk);

					/* TODO de-HTML-ify */
					/* TODO validate psk */

					if (set_wifi_psk(psk) != 0) {
						printf("Status: 500 Internal Server Error\n");
						error = "\"Unable to save PSK.\"";
					}
				} else if (yajl_psk == NULL) {
					char* ssid = YAJL_GET_STRING(yajl_ssid);

					/* TODO de-HTML-ify */
					/* TODO validate ssid */

					if (set_wifi_ssid(ssid) != 0) {
						printf("Status: 500 Internal Server Error\n");
						error = "\"Unable to save SSID.\"";
					}
				}

				yajl_tree_free(top);
				free(data);

				printf("Content-type: application/json\n\n");
		
				char* empty = "";
				char* ssid = empty;
				char* psk = empty;

				get_wifi_vals(&ssid, &psk);

				/* TODO JSON-escape the ssid and psk */

				printf("{\"ssid\":\"%s\",\"psk\":\"%s\"", ssid, psk);
				if (error != NULL && strlen(error) != 0) {
					printf(",\"errors\":[%s]}", error);
				} else {
					printf("}");
				}

				if (ssid != empty) {
					free(ssid);
				}
				if (psk != empty) {
					free(psk);
				}
			}
		} else {
			printf("Status: 405 Method Not Allowed\n");
			printf("Allow: POST\n");
			printf("{\"errors\":[\"Received HTTP method other than GET, POST, or HEAD.\"]}");
		}

#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

