#include <config.h>

#include "update.h"

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <curl/curl.h>
#include <yajl/yajl_tree.h>
#include <uci.h>
#include <polarssl/md5.h>

#define SUI_MODEL_PATH "sui.system.model"

#define BASE_URL "https://www.whoisonmywifi.net/hw/"
#define LATEST_JSON_URL BASE_URL "latest.json"
#define CA_FILE "/etc/ssl/certs/f081611a.0"
#define UPGRADE_FILE "/tmp/sysupgrade.bin"
#define OUTPUT_FILE "/tmp/sysupgrade.log"
#define REBOOT_DELAY "15"
#define POLL_DELAY "15"
#define JSON_ERROR_BUFFER_LEN 1024
#define MINIMUM_EXTRA_MEMORY 2097152

#define FREE_COMMAND "free | awk '$1 == \"Mem:\" {print $4;}'"
#define MD5_COMMAND "md5sum " UPGRADE_FILE
#define SYSUPGRADE_COMMAND "sysupgrade -v -d " REBOOT_DELAY " " UPGRADE_FILE " >> " OUTPUT_FILE " 2>> " OUTPUT_FILE " || echo 1 &  sleep " POLL_DELAY " && echo 0 & "

struct data_holder {
	size_t offset;
	char data[];
};

int version_compare(char* new)
{
	if (strcmp(VERSION "-r" RELEASE_NUMBER, new) == 0) {
		return 0;
	} else {
		/* TODO: Version compare instead of just version validity */
		unsigned short state = 0;
		size_t i = 0;
		for (i = 0; new[i] != '\0'; i++) {
			switch (state) {
			case 0:
				if (isdigit(new[i])) {
					state = 1;
				} else {
					return -1;
				}
				break;
			case 1:
				if (new[i] == '.') {
					state = 2;
				} else if (new[i] == '-') {
					state = 3;
				} else if (isdigit(new[i])) {
					state = 1;
				} else {
					return -1;
				}
				break;
			case 2:
				if (isdigit(new[i])) {
					state = 1;
				} else {
					return -1;
				}
				break;
			case 3:
				if (new[i] == 'r') {
					state = 4;
				} else {
					return -1;
				}
				break;
			case 4:
				if (isdigit(new[i])) {
					state = 4;
				} else {
					return -1;
				}
				break;
			}
		}
		if (state == 1 || state == 4) {
			return 1;
		} else {
			return -1;
		}
	}
}

static size_t latest_json_cb(void* buffer, size_t size, size_t nmemb, void* raw_holder)
{
	size_t count = 0;
	struct data_holder* holder;

	if (raw_holder == NULL) {
		return 0;
	}

	if (*(void**)raw_holder == NULL) {
		*(void**)raw_holder = malloc(sizeof(struct data_holder) + (size * nmemb) + 1);
		(*(struct data_holder**)raw_holder)->offset = 0;
	} else {
		*(void**)raw_holder = realloc(*(void**)raw_holder, sizeof(struct data_holder) + (*(struct data_holder**)raw_holder)->offset + (size * nmemb) + 1);
	}
	holder = *(struct data_holder**)raw_holder;
	if (holder == NULL) {
		return 0;
	}

	for (count = 0; count < nmemb; count++) {
		memcpy(holder->data + holder->offset, (char*)buffer + (count * size), size);
		holder->offset += size;
	}
	holder->data[holder->offset] = '\0';

	return count * size;
}

static struct data_holder*  get_latest_json()
{
	CURL* curl_handle = curl_easy_init();
	struct data_holder* holder = NULL;
	char error_buffer[BUFSIZ];
	long http_code = 0;

	curl_easy_setopt(curl_handle, CURLOPT_URL, LATEST_JSON_URL);
	curl_easy_setopt(curl_handle, CURLOPT_CAINFO, CA_FILE);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, &latest_json_cb);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, &holder);
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, error_buffer);

	if (curl_easy_perform(curl_handle) == 0 && curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code) == 0) {
		if (holder == NULL) {
			curl_easy_cleanup(curl_handle);
			free(holder);
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"The router is out of memory and needs to be restarted immediately.\"]}");
			syslog(LOG_EMERG, "Unable to allocate memory");
			return NULL;
		} else if (http_code >= 400) {
			curl_easy_cleanup(curl_handle);
			free(holder);
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while contacting update server.\"]}");
			syslog(LOG_WARNING, "Unable to get latest.json, got HTTP code: %lu", http_code);
			return NULL;
		} else {
			curl_easy_cleanup(curl_handle);
			return holder;
		}
	} else {
		/* curl failure (probably network failure) */
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Error while contacting update server.\"]}");
		syslog(LOG_ERR, "Unable to connect to update server: %s", error_buffer);
		curl_easy_cleanup(curl_handle);
		return NULL;
	}
}

const char* get_update_file(const char* url)
{
	CURL* curl_handle = curl_easy_init();
	char error_buffer[BUFSIZ];
	FILE* update_file;
	long http_code = 0;
	char full_url[BUFSIZ];

	if ((update_file = fopen(UPGRADE_FILE, "w")) == NULL) {
		syslog(LOG_ERR, "Unable to open update file for writing: %s", strerror(errno));
		return "Error while preparing update file.";
	}

	snprintf(full_url, BUFSIZ, BASE_URL "%s", url);

	curl_easy_setopt(curl_handle, CURLOPT_URL, full_url);
	curl_easy_setopt(curl_handle, CURLOPT_CAINFO, CA_FILE);
	curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, update_file);
	curl_easy_setopt(curl_handle, CURLOPT_ERRORBUFFER, error_buffer);

	if (curl_easy_perform(curl_handle) == 0 && curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &http_code) == 0) {
		if (http_code >= 400) {
			curl_easy_cleanup(curl_handle);
			syslog(LOG_WARNING, "Unable to get update file, got HTTP code: %lu", http_code);
			fclose(update_file);
			return "Error while contacting update server.";
		} else {
			curl_easy_cleanup(curl_handle);
			fclose(update_file);
			return NULL;
		}
	} else {
		/* curl failure (probably network failure) */
		syslog(LOG_ERR, "Unable to connect to update server: %s", error_buffer);
		curl_easy_cleanup(curl_handle);
		fclose(update_file);
		return "Error while contacting update server.";
	}
}

void post_update(yajl_val api_yajl)
{
	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	char sui_model[BUFSIZ];
	struct data_holder* holder = NULL;
	yajl_val latest_yajl = NULL;
	yajl_val latest_version_yajl = NULL;
	char errbuff[JSON_ERROR_BUFFER_LEN];
	ctx = uci_alloc_context();

	strncpy(uci_lookup_str, SUI_MODEL_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) == UCI_OK
			&& (ptr.flags & UCI_LOOKUP_COMPLETE) != 0) {
		strncpy(sui_model, ptr.o->v.string, BUFSIZ);
	} else {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to determine router model.\"]}");
		syslog(LOG_ERR, "Unable to retrieve router model from uci at "SUI_MODEL_PATH);
		return;
	}

	/* const char* device_path[] = {JSON_DEVICE_NAME, (const char*)0}; */
	const char* latest_version_path[] = {sui_model, "version", (const char*)0};

	if ((holder = get_latest_json()) == NULL) {
		/* error getting latest.json (error message has already been sent via cgi). */
		return;
	} else if ((latest_yajl = yajl_tree_parse(holder->data, errbuff, JSON_ERROR_BUFFER_LEN)) == NULL || !YAJL_IS_OBJECT(latest_yajl)) {
		/* unable to parse latest.json */
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Error while reading update information from server.\"]}");
		syslog(LOG_ERR, "Unable to parse latest.json: %s", errbuff);
		free(holder);
		return;
	} else if ((latest_version_yajl = yajl_tree_get(latest_yajl, latest_version_path, yajl_t_string)) == NULL) {
		/* no/invalid update version in latest.json */
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Error while reading update version number for device.\"]}");
		syslog(LOG_ERR, "Unable to retrieve update version number from latest.json.");
		free(holder);
		return;
	} else if (version_compare(YAJL_GET_STRING(latest_version_yajl)) > 0) {
		/* update available */
		yajl_val latest_size_yajl = NULL;
		yajl_val latest_url_yajl = NULL;
		yajl_val latest_md5_yajl = NULL;
		yajl_val api_version_yajl = NULL;
		yajl_val api_size_yajl = NULL;
		yajl_val api_md5_yajl = NULL;
		const char* latest_size_path[] = {sui_model, "size", (const char*)0};
		const char* latest_url_path[] = {sui_model, "url", (const char*)0};
		const char* latest_md5_path[] = {sui_model, "md5", (const char*)0};
		const char* api_version_path[] = {"version", (const char*)0};
		const char* api_size_path[] = {"size", (const char*)0};
		const char* api_md5_path[] = {"md5", (const char*)0};
		if ((latest_size_yajl = yajl_tree_get(latest_yajl, latest_size_path, yajl_t_number)) == NULL
				|| (latest_url_yajl = yajl_tree_get(latest_yajl, latest_url_path, yajl_t_string)) == NULL
				|| (latest_md5_yajl = yajl_tree_get(latest_yajl, latest_md5_path, yajl_t_string)) == NULL) {
			/* unable to get everything from latest.json */
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while reading update file information.\"]}");
			syslog(LOG_ERR, "Unable to retrieve update file info from latest.json.");
			free(holder);
			return;
		}
		if ((api_version_yajl = yajl_tree_get(api_yajl, api_version_path, yajl_t_string)) != NULL) {
			/* user is trying to perform an upgrade with an already-present update file */
			if ((api_size_yajl = yajl_tree_get(api_yajl, api_size_path, yajl_t_number)) == NULL
					|| (api_md5_yajl = yajl_tree_get(api_yajl, api_md5_path, yajl_t_string)) == NULL) {
				/* user did not provide all required data */
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Version, size (in bytes, as a number), and md5 must be supplied before an update will be applied.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				free(holder);
				return;
			} else if (strcmp(YAJL_GET_STRING(latest_version_yajl), YAJL_GET_STRING(api_version_yajl)) != 0
					|| YAJL_GET_INTEGER(latest_size_yajl) != YAJL_GET_INTEGER(api_size_yajl)
					|| strcmp(YAJL_GET_STRING(latest_md5_yajl), YAJL_GET_STRING(api_md5_yajl)) != 0) {
				/* user's data doesn't match latest.json */
				printf("Status: 422 Unprocessable Entity\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"The version, size, and md5 supplied did not match the corresponding values that were expected.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				free(holder);
				return;
			}
		}
		struct stat stat_res;
		unsigned char raw_hash[16];
		char hash[33];
		FILE* command_output;
		if (stat(UPGRADE_FILE, &stat_res) != 0) {
			/* issue reading old update file (it probably hasn't been downloaded yet, which is normal) */
			int my_errno;
			if ((my_errno = errno) != ENOENT) {
				/* issue reading old update file isn't simply that it doesn't exist yet */
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				syslog(LOG_ERR, "Unable to stat the old update file: %s", strerror(my_errno));
				free(holder);
				return;
			}
		} else if (stat_res.st_size != YAJL_GET_INTEGER(latest_size_yajl)) {
			/* old update file was wrong size, so it should be removed and replaced */
			syslog(LOG_WARNING, "Size of previously downloaded update file is wrong, deleting it.");
			if (remove(UPGRADE_FILE) != 0) {
				/* unable to remove old update file */
				int my_errno = errno;
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				syslog(LOG_ERR, "Unable to remove the old incorrect size update file: %s", strerror(my_errno));
				free(holder);
				return;
			}
		} else if ((command_output = popen(MD5_COMMAND, "r")) == NULL) {
			/* unable to get md5 of old update file */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unable to md5 the old update file: %s", strerror(my_errno));
			free(holder);
			return;
		} else if (fgets(hash, 33, command_output) == NULL) {
			/* unable to reformat md5 (very weird) */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unable to parse raw md5 of the old update file: %s", strerror(my_errno));
			free(holder);
			return;
		} else if (strcmp(YAJL_GET_STRING(latest_md5_yajl), hash) != 0) {
			/* old update file has wrong md5, so it should be removed and replaced */
			syslog(LOG_WARNING, "MD5 of previously downloaded update file is wrong, deleting it.");
			if (remove(UPGRADE_FILE) != 0) {
				/* unable to remove old update file */
				int my_errno = errno;
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				syslog(LOG_ERR, "Unable to remove the old incorrect md5 update file: %s", strerror(my_errno));
				free(holder);
				return;
			}
		} else if (api_version_yajl != NULL) {
			/* old update file is legit and user has authorized upgrade */
			if (pclose(command_output) != 0 || (command_output = popen(SYSUPGRADE_COMMAND, "r")) == NULL) {	
				/* unable to open shell */
				int my_errno = errno;
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Error while starting the upgrade.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"ready\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				syslog(LOG_ERR, "Unable to popen the sysupgrade command: %s", strerror(my_errno));
				free(holder);
				return;
			} else if (fgetc(command_output) != '0') {
				/* got non-zero return code from sysupgrade */
				printf("Status: 500 Internal Server Error\n");
				printf("Content-type: application/json\n\n");
				printf("{\"errors\":[\"Error while performing the upgrade.\"],");
				printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"ready\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
				syslog(LOG_ERR, "The sysupgrade command failed.");
				free(holder);
				pclose(command_output);
				return;
			} else {
				/* upgrade complete */
				printf("Status: 200 OK\n");
				printf("Content-type: application/json\n\n");
				printf("{\"update\":\"complete\",\"rebooting\":true}");
				free(holder);
				pclose(command_output);
				return;
			}
		} else {
			/* old update file is legit, but user has not authorized upgrade */
			printf("Status: 200 OK\n");
			printf("Content-type: application/json\n\n");
			printf("{\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"ready\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			free(holder);
			return;
		}
		/* new update file should be downloaded */
		size_t free_mem;
		const char* curl_error = NULL;
		if ((command_output = popen(FREE_COMMAND, "r")) == NULL) {
			/* unable to open a shell */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while checking for available memory.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unable to popen the free command: %s", strerror(my_errno));
			free(holder);
			return;
		} else if (fscanf(command_output, "%zu", &free_mem) != 1) {
			/* perhaps didn't get a numeric output from free, more likely had some other problem reading it */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while checking for available memory.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unexpected results or read error for free command: %s", strerror(my_errno));
			free(holder);
			pclose(command_output);
			return;
		} else if ((free_mem * 1024) < YAJL_GET_INTEGER(latest_size_yajl) + MINIMUM_EXTRA_MEMORY) {
			/* insufficient memory to download new update file */
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Insufficient free memory to download update file. Restarting the router will likely solve this problem.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Insufficient memory to download the update.");
			free(holder);
			pclose(command_output);
			return;
		} else if ((curl_error = get_update_file(YAJL_GET_STRING(latest_url_yajl))) != NULL) {
			/* error during download of new update file */
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"%s\"],", curl_error);
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			free(holder);
			pclose(command_output);
			return;
		} else if (stat(UPGRADE_FILE, &stat_res) != 0) {
			/* unable to access new update file */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unable to stat the new update file: %s", strerror(my_errno));
			free(holder);
			pclose(command_output);
			return;
		} else if (stat_res.st_size != YAJL_GET_INTEGER(latest_size_yajl)) {
			/* new update file was the wrong size */
			remove(UPGRADE_FILE);
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Downloaded update file was the wrong size.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			free(holder);
			pclose(command_output);
			return;
		} else if (pclose(command_output) != 0 || (command_output = popen(MD5_COMMAND, "r")) == NULL) {
			/* unable to get md5 of new update file */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unable to md5 the new update file: %s", strerror(my_errno));
			free(holder);
			pclose(command_output);
			return;
		} else if (fgets(hash, 33, command_output) == NULL) {
			/* unable to reformat md5 (very weird) */
			int my_errno = errno;
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Error while reading the downloaded update file.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			syslog(LOG_ERR, "Unable to parse raw md5 of the new update file: %s", strerror(my_errno));
			free(holder);
			pclose(command_output);
			return;
		} else if (strcmp(YAJL_GET_STRING(latest_md5_yajl), hash) != 0) {
			/* md5 of new update file didn't match */
			remove(UPGRADE_FILE);
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Downloaded update file did not have the correct md5.\"],");
			printf("\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"available\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			free(holder);
			pclose(command_output);
			return;
		} else {
			/* new update file looks good */
			printf("Status: 200 OK\n");
			printf("Content-type: application/json\n\n");
			printf("{\"version\":\"%s\",\"size\":%lld,\"md5\":\"%s\",\"update\":\"ready\"}", YAJL_GET_STRING(latest_version_yajl), YAJL_GET_INTEGER(latest_size_yajl), YAJL_GET_STRING(latest_md5_yajl));
			free(holder);
			pclose(command_output);
			return;
		}
	} else {
		/* no update available */
		printf("Status: 200 OK\n");
		printf("Content-type: application/json\n\n");
		printf("{\"update\":\"none\"}");
		free(holder);
		return;
	}
}

