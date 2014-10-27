#include <config.h>
#include "reboot.h"

#include <stdio.h>
#include <stdlib.h>

#define REBOOT_COMMAND "sleep 3 && reboot &"

void post_reboot()
{
	if (system(REBOOT_COMMAND) == -1) {
		printf("Status: 500 Internal Server Error\n");
		printf("Content-type: application/json\n\n");
		printf("{\"rebooting\":0,\"errors\":[\"Unable to reboot system.\"]}");
		return;
	}
	printf("Status: 200 OK\n");
	printf("Content-type: application/json\n\n");
	printf("{\"rebooting\":1}");
}

