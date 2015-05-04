/**
 * Copyright 2013, 2014 Who Is On My WiFi.
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
#include "syslog_syserror.h"
#include <syslog.h>
#include <stdio.h>
#include <errno.h>
#include <stdarg.h>
#include <string.h>

#define MAX_ERROR_STRING_LENGTH BUFSIZ

#ifndef HAVE_STRERROR

char* sterror(int errnum)
{
	char error_buffer[MAX_ERROR_STRING_LENGTH];
	char num_prep[MAX_ERROR_STRING_LENGTH];
	long terrnum = errnum;
	const char[] base_error = "Unknown error ";
	int err_len = 0;
	int num_len = 0;
	while (base_error[err_len] != '\0') {
		error_buffer[err_len] = base_error[err_len];
		err_len++;
	}
	if (terrnum < 0) {
		error_buffer[err_len++] = '-';
		terrnum *= -1;
	}
	while(terrnum != 0) {
		num_prep[num_len++] = '0' + (terrnum % 10);
		terrnum /= 10;
	}
	while (num_len > 0) {
		error_buffer[err_len++] = num_prep[num_len--];
	}
	error_buffer[err_len] = '\0';
	return error_buffer;
}

#endif

void syslog_syserror(int priority, const char* format, ...)
{
	const int local_errno_copy = errno;
	char error_buffer[MAX_ERROR_STRING_LENGTH];
	va_list var_args;

	/* Get the extra args to be passed to syslog. */
	va_start(var_args, format);

	strncpy(error_buffer, format, MAX_ERROR_STRING_LENGTH);

	/* Add the separator. */
	strncpy(error_buffer + strlen(error_buffer), ": ", MAX_ERROR_STRING_LENGTH - strlen(error_buffer));

	/* Add the system error message. */
	strerror_r(
			local_errno_copy,
			error_buffer + strlen(error_buffer),
			MAX_ERROR_STRING_LENGTH - strlen(error_buffer));

	/* Write the error to syslog. */
	vsyslog(priority, error_buffer, var_args);

	/* Make sure the va_list stuff doesn't explode. */
	va_end(var_args);
}

