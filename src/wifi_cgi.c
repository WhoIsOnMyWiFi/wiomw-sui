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

#define JSON_ERROR_BUFFER_LEN 1024

int main()
{
#if HAVE_FCGI_STDIO_H
	while (FCGI_Accept() >= 0) {
#endif
		char* method = getenv("REQUEST_METHOD");
		char error[BUFSIZ] = "";
		char* errptr = error;
		if (method == NULL) {
			printf("Status: 400 Bad Request\n");
			printf("Allow: GET, POST, HEAD\n");
			errptr = stpcpy(errptr, ",\"Unable to determine HTTP method.\"");
		} else if (strcmp(method, "POST") == 0) {
			unsigned long int length = strtoul(getenv("CONTENT_LENGTH"), NULL, 0);
			char* data = (char*)malloc(length);
			char yajl_err_buf[JSON_ERROR_BUFFER_LEN];
			yajl_val top;
			size_t bytes = fread(data, 1, length, stdin);
			if (bytes != length && !feof(stdin)) {
				printf("Status: 500 Internal Server Error\n");
				errptr = stpcpy(errptr, ",\"Error while reading POST data.\"");
				free(data);
			} else if (((top = yajl_tree_parse(data, yajl_err_buf, JSON_ERROR_BUFFER_LEN)) == NULL) || YAJL_IS_ARRAY(top)) {
				printf("Status: 422 Unprocessable Entity\n");
				errptr = stpcpy(errptr, ",\"Unable to parse data as JSON object.\"");
				yajl_tree_free(top);
				free(data);
			} else {
				const char* ssid_path[] = {"ssid", (const char*)0};
				const char* psk_path[] = {"psk", (const char*)0};
				yajl_val yajl_ssid = yajl_tree_get(top, ssid_path, yajl_t_string);
				yajl_val yajl_psk = yajl_tree_get(top, psk_path, yajl_t_string);
				if (yajl_ssid == NULL && yajl_psk == NULL) {
					printf("Status: 422 Unprocessable Entity\n");
					errptr = stpcpy(errptr, ",\"No SSID and no PSK were found.\"");
				} else if (yajl_ssid == NULL) {
					char* psk = YAJL_GET_STRING(yajl_psk);
					/* TODO de-HTML-ify */
					/* TODO validate psk */
					if (set_wifi_psk(psk) != 0) {
						printf("Status: 500 Internal Server Error\n");
						errptr = stpcpy(errptr, ",\"Unable to save PSK.\"");
					}
				} else if (yajl_psk == NULL) {
					char* ssid = YAJL_GET_STRING(yajl_ssid);
					/* TODO de-HTML-ify */
					/* TODO validate ssid */
					if (set_wifi_ssid(ssid) != 0) {
						printf("Status: 500 Internal Server Error\n");
						errptr = stpcpy(errptr, ",\"Unable to save SSID.\"");
					}
				} else {
					char* ssid = YAJL_GET_STRING(yajl_ssid);
					char* psk = YAJL_GET_STRING(yajl_psk);
					/* TODO de-HTML-ify */
					/* TODO validate ssid */
					/* TODO validate psk */
					if (set_wifi_vals(ssid, psk) != 0) {
						printf("Status: 500 Internal Server Error\n");
						errptr = stpcpy(errptr, ",\"Unable to save SSID and PSK.\"");
					}
				}
				yajl_tree_free(top);
				free(data);
			}
		} else if (strcmp(method, "GET") != 0 && strcmp(method, "HEAD") != 0) {
			printf("Status: 405 Method Not Allowed\n");
			printf("Allow: GET, POST, HEAD\n");
			errptr = stpcpy(errptr, ",\"Received HTTP method other than GET, POST, or HEAD.\"");
		}

		printf("Content-type: application/json\n\n");

		if (strcmp(method, "HEAD") != 0) {
			char* ssid = NULL;
			char* psk = NULL;
			get_wifi_vals(&ssid, &psk);
			/* TODO JSON-escape the ssid and psk */
			printf("{\"ssid\":\"%s\",\"psk\":\"%s\"", ssid, psk);
			if (strlen(error) != 0) {
				printf(",\"errors\":[%s]}", error + 1);
			} else {
				printf("}");
			}
			free(ssid);
			free(psk);
		}
#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

