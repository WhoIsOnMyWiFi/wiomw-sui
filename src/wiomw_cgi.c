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

#include "wiomw_uci.h"

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
				const char* agentkey_path[] = {"agentkey", (const char*)0};
				const char* username_path[] = {"username", (const char*)0};
				const char* passhash_path[] = {"passhash", (const char*)0};
				yajl_val yajl_agentkey = yajl_tree_get(top, agentkey_path, yajl_t_string);
				yajl_val yajl_username = yajl_tree_get(top, username_path, yajl_t_string);
				yajl_val yajl_passhash = yajl_tree_get(top, passhash_path, yajl_t_string);
				if (yajl_agentkey == NULL && yajl_username == NULL && yajl_passhash == NULL) {
					printf("Status: 422 Unprocessable Entity\n");
					errptr = stpcpy(errptr, ",\"No agentkey, username, or passhash were found.\"");
				} else if (yajl_agentkey != NULL && yajl_username != NULL && yajl_passhash != NULL) {
					char* agentkey = YAJL_GET_STRING(yajl_agentkey);
					char* username = YAJL_GET_STRING(yajl_username);
					char* passhash = YAJL_GET_STRING(yajl_passhash);
					/* TODO de-HTML-ify */
					/* TODO some validation */
					if (set_wiomw_vals(agentkey, username, passhash) != 0) {
						printf("Status: 500 Internal Server Error\n");
						errptr = stpcpy(errptr, ",\"Unable to save agentkey, username, and passhash.\"");
					}
				} else {
					if (yajl_agentkey != NULL) {
						char* agentkey = YAJL_GET_STRING(yajl_agentkey);
						/* TODO de-HTML-ify */
						/* TODO some validation */
						if (set_wiomw_agentkey(agentkey) != 0) {
							printf("Status: 500 Internal Server Error\n");
							errptr = stpcpy(errptr, ",\"Unable to save agentkey.\"");
						}
					}
					if (yajl_username != NULL) {
						char* username = YAJL_GET_STRING(yajl_username);
						/* TODO de-HTML-ify */
						/* TODO some validation */
						if (set_wiomw_username(username) != 0) {
							printf("Status: 500 Internal Server Error\n");
							errptr = stpcpy(errptr, ",\"Unable to save username.\"");
						}
					}
					if (yajl_passhash != NULL) {
						char* passhash = YAJL_GET_STRING(yajl_passhash);
						/* TODO de-HTML-ify */
						/* TODO some validation */
						if (set_wiomw_passhash(passhash) != 0) {
							printf("Status: 500 Internal Server Error\n");
							errptr = stpcpy(errptr, ",\"Unable to save passhash.\"");
						}
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

		if (method == NULL || strcmp(method, "HEAD") != 0) {
			char* empty = "";
			char* agentkey = empty;
			char* username = empty;
			char* passhash = empty;
			get_wiomw_vals(&agentkey, &username, &passhash);
			/* TODO JSON-escape */
			printf("{\"agentkey\":\"%s\",\"username\":\"%s\",\"passhash\":\"%s\"", agentkey, username, passhash);
			if (strlen(error) != 0) {
				printf(",\"errors\":[%s]}", error + 1);
			} else {
				printf("}");
			}
			if (agentkey != empty) {
				free(agentkey);
			}
			if (username != empty) {
				free(username);
			}
			if (passhash != empty) {
				free(passhash);
			}
		}
#if HAVE_FCGI_STDIO_H
	}
#endif

	return 0;
}

