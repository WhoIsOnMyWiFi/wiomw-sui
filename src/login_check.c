#include <config.h>
#include "login_check.h"

#include <stdbool.h>
#include <shadow.h>
#include <stdlib.h>
#include <string.h>
#include <crypt.h>

bool login_check(const char* password)
{
	struct spwd* spass = getspnam("root");
	char* hash = NULL;

	if (strlen(spass->sp_pwdp) < 5 || (spass->sp_pwdp)[0] != '$') {
		return false;
	} else if ((hash = crypt(password, spass->sp_pwdp)) == NULL) {
		return false;
	} else {
		return (strcmp(hash, spass->sp_pwdp) == 0);
	}
}

