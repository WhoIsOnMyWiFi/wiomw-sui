#include <config.h>
#include "password.h"

#include <crypt.h>
#include <shadow.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <polarssl/sha512.h>
#include <yajl/yajl_tree.h>
#include <uci.h>
#include "urandom.h"
#include "xsrf.h"
#include "xsrfc.h"

#define PASSWORD_CHECK_WAIT 5
#define CRED_CHECK_WAIT 2

#define CRED_RANDOM_DATA_LEN 20

#define WIFI_CHANGED_UCI_PATH "sui.changed.wifi"

#define PARTIAL_PASSWD_CMD "passwd >/dev/null; echo $? > "

void post_password(yajl_val top)
{
	const char* password_yajl_path[] = {"password", (const char*)0};
	yajl_val password_yajl = yajl_tree_get(top, password_yajl_path, yajl_t_string);

	if (password_yajl == NULL) {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Password is required.\"]}");
		return;
	}

	char* password = YAJL_GET_STRING(password_yajl);
	if (strlen(password) == 0) {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: available/json\n\n");
		printf("{\"errors\":[\"Invalid password.\"]}");
		return;
	}
	/* TODO: sanitize? */


	char* hash = NULL;
	struct spwd* spass = getspnam("root");
	if (spass == NULL) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve password hash.\"]}");
		return;
	}

	bool valid_password = false;
	if (strlen(spass->sp_pwdp) < 3) {
		char passwd_cmd[BUFSIZ] = PARTIAL_PASSWD_CMD "/tmp/sui-error-XXXXXX";
		char* tempfile = passwd_cmd + strlen(PARTIAL_PASSWD_CMD);
		int tfd = -1;
		if ((tfd = mkstemp(tempfile)) == -1) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to set password (unable to create file).\"]}");
			return;
		}

		FILE* passwd_input;
		if ((passwd_input = popen(passwd_cmd, "w")) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to set password (unable to begin process).\"]}");
			close(tfd);
			remove(tempfile);
			return;
		}
		fprintf(passwd_input, "%s\n%s\n", password, password);
		pclose(passwd_input);

		FILE* passwd_result = fdopen(tfd, "r");
		rewind(passwd_result);
		if (fgetc(passwd_result) != '0') {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to set password (failure during the process).\"]}");
			fclose(passwd_result);
			remove(tempfile);
			return;
		}

		fclose(passwd_result);
		remove(tempfile);

		if ((spass = getspnam("root")) == NULL) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to retrieve password hash.\"]}");
			return;
		}

		valid_password = true;
	} else if ((hash = crypt(password, spass->sp_pwdp)) == NULL) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to hash password.\"]}");
		return;
	} else if (strcmp(hash, spass->sp_pwdp) == 0) {
		valid_password = true;
	}

	int xsrfc_status = -1;
	struct xsrft token;
	token.val[0] = (char)0x00;
	if ((xsrfc_status = xsrfc(&token)) < 0 && sleep(PASSWORD_CHECK_WAIT) != 0) {
		/* Failed to sleep? That sounds suspicious.... */
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		/* ...so how about a unique but tricksy error message? */
		printf("{\"errors\":[\"Unable to hash pasword.\"]}");
		return;
	}

	if (!valid_password) {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Invalid password.\"]}");
		return;
	}

	if (xsrfc_status == 0) {
		/* well, something's screwy.... */
		syslog(LOG_ERR, "Received XSRFC status 0 in response to a null call");
	}

	char psalt_and_shash[BUFSIZ];
	char phash[129];
	if (xsrfc_status <= 0) {
		unsigned char raw_psalt[CRED_RANDOM_DATA_LEN];
	
		if (urandom(raw_psalt, CRED_RANDOM_DATA_LEN) < 0) {
			printf("Status: 500 Internal Server Error\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Unable to hash passwod.\"]}");
			return;
		}
	
		char* tpsalt = psalt_and_shash;
		unsigned char* traw_psalt = raw_psalt;
		for (traw_psalt = raw_psalt; traw_psalt - raw_psalt < CRED_RANDOM_DATA_LEN; traw_psalt++) {
			sprintf(tpsalt, "%02X", *traw_psalt);
			tpsalt += 2;
		}
	
		strncpy(psalt_and_shash + (CRED_RANDOM_DATA_LEN * 2), spass->sp_pwdp, BUFSIZ - (CRED_RANDOM_DATA_LEN * 2));
	
		unsigned char raw_phash[64];
	
		sha512((unsigned char*)psalt_and_shash, strnlen(psalt_and_shash, BUFSIZ), raw_phash, 0);
	
		char* tphash = phash;
		unsigned char* traw_phash = raw_phash;
		for (traw_phash = raw_phash; traw_phash - raw_phash < 64; traw_phash++) {
			sprintf(tphash, "%02X", *traw_phash);
			tphash += 2;
		}
	
		/* so we don't have to copy the psalt elsewhere... */
		psalt_and_shash[CRED_RANDOM_DATA_LEN * 2] = '\0';
	}

	struct uci_context* ctx;
	struct uci_ptr ptr;
	int res = 0;
	char uci_lookup_str[BUFSIZ];
	bool setup = false;
	ctx = uci_alloc_context();

	strncpy(uci_lookup_str, WIFI_CHANGED_UCI_PATH, BUFSIZ);
	if ((res = uci_lookup_ptr(ctx, &ptr, uci_lookup_str, true)) != UCI_OK) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to determine setup status.\"]}");
		return;
	} else if ((ptr.flags & UCI_LOOKUP_COMPLETE) != 0) {
		setup = true;
	}

	printf("Status: 200 OK\n");
	printf("Content-type: application/json\n\n");

	if (xsrfc_status > 0) {
		printf("{\"xsrf\":\"%s\"", token.val);
	} else {
		printf("{\"psalt\":\"%s\",\"phash\":\"%s\"", psalt_and_shash, phash);
		if (xsrfc_status == 0) {
			printf(",\"errors\":[\"The normal login system behaved strangely, but the backup login system worked.\"]");
		} else {
			printf(",\"errors\":[\"The normal login system was down, but the backup login system worked.\"]");
		}
	}

	if (!setup) {
		printf(",\"setup_required\":true}");
	} else {
		printf(",\"setup_required\":false}");
	}
}

bool valid_creds(yajl_val top, struct xsrft* token)
{
	const char* xsrf_yajl_path[] = {"xsrf", (const char*)0};
	int xsrfc_status = -1;
	yajl_val xsrf_yajl = yajl_tree_get(top, xsrf_yajl_path, yajl_t_string);
	char* xsrf_val = NULL;

	if (xsrf_yajl != NULL && (xsrf_val = YAJL_GET_STRING(xsrf_yajl)) != NULL) {
		strncpy(token->val, xsrf_val, XSRF_TOKEN_HEX_LENGTH + 1);
		token->val[XSRF_TOKEN_HEX_LENGTH] = '\0';
		if ((xsrfc_status = xsrfc(token)) == 0) {
			printf("Status: 403 Forbidden\n");
			printf("Content-type: application/json\n\n");
			printf("{\"errors\":[\"Invalid credentials.\"]}");
			return false;
		} else if (xsrfc_status > 0) {
			return true;
		}
	}

	token->val[0] = '\0';

	const char* psalt_yajl_path[] = {"psalt", (const char*)0};
	const char* phash_yajl_path[] = {"phash", (const char*)0};
	yajl_val psalt_yajl = yajl_tree_get(top, psalt_yajl_path, yajl_t_string);
	yajl_val phash_yajl = yajl_tree_get(top, phash_yajl_path, yajl_t_string);
	char* psalt;
	char* ephash;

	if (psalt_yajl == NULL || phash_yajl == NULL) {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"You are not logged in.\"]}");
		return false;
	} else if ((psalt = YAJL_GET_STRING(psalt_yajl)) == NULL
			|| (ephash = YAJL_GET_STRING(phash_yajl)) == NULL
			|| strnlen(psalt, BUFSIZ) != (CRED_RANDOM_DATA_LEN * 2)
			|| strnlen(ephash, BUFSIZ) != 128) {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Invalid credentials.\"]}");
		return false;
	}

	struct spwd* spass = getspnam("root");
	if (spass == NULL) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Unable to retrieve internal credentials.\"]}");
		return false;
	}

	char psalt_and_shash[BUFSIZ];
	strcpy(psalt_and_shash, psalt);
	strncpy(psalt_and_shash + (CRED_RANDOM_DATA_LEN * 2), spass->sp_pwdp, BUFSIZ - (CRED_RANDOM_DATA_LEN * 2));

	unsigned char raw_aphash[64];
	char aphash[129];

	sha512((unsigned char*)psalt_and_shash, strnlen(psalt_and_shash, BUFSIZ), raw_aphash, 0);

	unsigned char* traw_aphash = raw_aphash;
	char* taphash = aphash;
	for (traw_aphash = raw_aphash; traw_aphash - raw_aphash < 64; traw_aphash++) {
		sprintf(taphash, "%02X", *traw_aphash);
		taphash += 2;
	}

	if (sleep(CRED_CHECK_WAIT) != 0) {
		/* Failed to sleep? That sounds suspicious.... */
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		/* ...so how about a unique but tricksy error message? */
		printf("{\"errors\":[\"Unable to retreve internal credentials.\"]}");
		return false;
	} else if (strcmp(ephash, aphash) != 0) {
		printf("Status: 403 Forbidden\n");
		printf("Content-type: application/json\n\n");
		printf("{\"errors\":[\"Invalid credentials.\"]}");
		return false;
	}

	return true;
}

