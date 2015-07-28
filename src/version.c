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
#include "version.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <yajl/yajl_tree.h>
#include "xsrf.h"

#define FULL_VERSION VERSION "-r" RELEASE_NUMBER

void post_version(yajl_val top, struct xsrft* token)
{
	printf("Status: 200 OK\n");
	printf("Content-type: application/json\n\n");
	printf("{\"version\":\""FULL_VERSION"\", \"xsrf\":\"%s\"}", token->val);
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


