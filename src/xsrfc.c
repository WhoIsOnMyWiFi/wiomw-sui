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
#include "xsrfc.h"
#include "xsrf.h"

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

int xsrfc(struct xsrft* token)
{
	struct sockaddr_un uaddr;
	int sock = 0;

	memset(&uaddr, 0x00, sizeof(struct sockaddr_un));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		return -1;
	}

	uaddr.sun_family = AF_UNIX;
	strcpy(uaddr.sun_path, XSRF_SOCK_PATH);

	if (connect(sock, (struct sockaddr*)&uaddr, sizeof(struct sockaddr_un)) == -1) {
		return -1;
	}

	if (send(sock, &(token->val), sizeof(struct xsrft), 0) == -1) {
		close(sock);
		return -1;
	}

	if (recv(sock, &(token->val), sizeof(struct xsrft), 0) < 0) {
		close(sock);
		return -1;
	}

	close(sock);

	if (token->val[0] == (char)0xff) {
		return -2;
	} else if (token->val[0] == (char)0x00) {
		return 0;
	} else {
		return 1;
	}
}

