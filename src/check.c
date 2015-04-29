#include <config.h>
#include "check.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <curl/curl.h>
#include <yajl/yajl_tree.h>
#include "reboot.h"
#include "syslog_syserror.h"
#include "xsrf.h"
#include "xsrfc.h"

#define CA_FILE "/etc/ssl/certs/f081611a.0"
#define CHECK_URL "https://www.whoisonmywifi.net/easteregg.txt"
#define CHECK_CABLE_COMMAND "cat /sys/class/net/`uci -q get network.wan.ifname`/carrier"

size_t identity_cb(char* ptr, size_t size, size_t nmemb, void* userdata)
{
	return size * nmemb;
}

static bool go_check(bool suppress)
{
	CURL* curl_handle = curl_easy_init();
	char error_buffer[BUFSIZ];
	long http_code = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, CHECK_URL);
	curl_easy_setopt(curl_handle, CURLOPT_CAINFO, CA_FILE);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &identity_cb);
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, error_buffer);

	if (curl_easy_perform(curl_handle) == 0 && curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code) == 0) {
		if (http_code >= 400) {
			curl_easy_cleanup(curl_handle);
			syslog(LOG_ERR, "Unable to check internet connection: Got unexpected HTTP code from server: %ld", http_code);
			if (!suppress) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to check connection to the internet.\"]}");
			}
			return false;
		} else {
			curl_easy_cleanup(curl_handle);
			if (!suppress) {
				printf("Status: 200 OK\n");
				printf("Content-type: application/json\n\n");
				printf("{\"connected\":true,\"cable_connected\":true}");
			}
			return true;
		}
	} else {
		FILE* command_output = popen(CHECK_CABLE_COMMAND, "r");
		char c = '\0';
		if (command_output == NULL) {
			curl_easy_cleanup(curl_handle);
			if (!suppress) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to check connection to the internet.\"]}");
			}
			return false;
		} else if ((c = fgetc(command_output)) == '0') {
			curl_easy_cleanup(curl_handle);
			if (!suppress) {
				printf("Status: 404 Not Found\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"WAN ethernet cable is not connected.\"], \"connected\":false,\"cable_connected\":false}");
			}
			return false;
		} else if (c == '1') {
			syslog(LOG_ERR, "Unable to connect to internet: %s", error_buffer);
			curl_easy_cleanup(curl_handle);
			/* curl failure (probably network failure) */
			if (!suppress) {
				printf("Status: 404 Not Found\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to connect to the internet.\"], \"connected\":false,\"cable_connected\":true}");
			}
			return false;
		} else {
			if (c == EOF) {
				syslog_syserror(LOG_ERR, "Unable to connect to internet: Unexpected response from cable check: Read error");
			} else {
				error_buffer[0] = c;
				fgets(error_buffer, BUFSIZ, command_output);
				syslog(LOG_ERR, "Unable to connect to internet: Unexpected response from cable check: %s", error_buffer);

			}
			curl_easy_cleanup(curl_handle);
			if (!suppress) {
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Unable to check connection to the internet.\"]}");
			}
			return false;
		}
	}
}

void get_check()
{
	go_check(false);
}

void get_check_reboot()
{
	struct xsrft token;
	token.val[0] = (char)0x00;
	if (!go_check(true) || xsrfc(&token) <= 0) {
		post_reboot();
	} else {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Nothing appears to be malfunctioning, so you must be logged in to reboot the router.\"]}");
	}
}

