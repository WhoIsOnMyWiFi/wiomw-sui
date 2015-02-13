#include <config.h>
#include "version.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <yajl/yajl_tree.h>

#define FULL_VERSION VERSION "-r" RELEASE_NUMBER

void post_version(yajl_val top)
{
	printf("Status: 200 OK\n");
	printf("Content-type: application/json\n\n");
	printf("{\"version\":\""FULL_VERSION"\"}");
	return;
}

int version_compare(char* new)
{
	if (strcmp(FULL_VERSION, new) == 0) {
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


