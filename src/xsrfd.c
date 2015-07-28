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
#include "xsrf.h"

#include <stdio.h>
#include <stdlib.h>
#include <sysexits.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "b2h.h"
#include "syslog_syserror.h"
#include "urandom.h"

#define XSRFD_QUEUE_LEN 5
#define XSRFD_MIN_ENTROPY 32
#define XSRFD_MAX_SESSION_CALLS 50
#define XSRFD_MAX_SESSION_TIME 600
#define XSRFD_CERTAIN_BRUTE_FORCE_COUNT 10
#define XSRFD_CERTAIN_BRUTE_FORCE_TIME 30
#define XSRFD_CERTAIN_BRUTE_FORCE_SLOWDOWN 5
#define XSRFD_POSSIBLE_BRUTE_FORCE_COUNT 3
#define XSRFD_POSSIBLE_BRUTE_FORCE_TIME 10
#define XSRFD_POSSIBLE_BRUTE_FORCE_SLOWDOWN 2
#define XSRFD_RECENT_DATE 0x54A48E00

int main()
{
	struct sockaddr_un uaddr;
	int sock = 0;
	struct xsrft stored;
	time_t login_attempts[XSRFD_CERTAIN_BRUTE_FORCE_COUNT];
	unsigned short session_calls = 0;
	size_t login_number = 0;

	for (login_number = 0; login_number < XSRFD_CERTAIN_BRUTE_FORCE_COUNT; login_number++) {
		login_attempts[login_number] = 0;
	}
	login_number = 0;

	openlog("XSRFD", 0, LOG_AUTHPRIV);

	memset(&uaddr, 0x00, sizeof(struct sockaddr_un));

	if ((sock = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		syslog_syserror(LOG_ALERT, "Unable to create unix socket");
		exit(EX_OSERR);
	}

	uaddr.sun_family = AF_UNIX;
	strcpy(uaddr.sun_path, XSRF_SOCK_PATH);
	unlink(XSRF_SOCK_PATH);
	if (bind(sock, (struct sockaddr*)&uaddr, sizeof(struct sockaddr_un)) == -1) {
		syslog_syserror(LOG_ALERT, "Unable to bind to unix socket");
		exit(EX_OSERR);
	}

	if (listen(sock, XSRFD_QUEUE_LEN) == -1) {
		syslog_syserror(LOG_ALERT, "Unable to listen on unix socket");
		exit(EX_OSERR);
	}

	while (1) {
		int tsock = 0;
		struct xsrft received;
		struct xsrft next;
		unsigned char randoms[XSRF_TOKEN_BINARY_LENGTH];
		time_t now = 0;

		if (urandom(randoms, XSRF_TOKEN_BINARY_LENGTH) < XSRFD_MIN_ENTROPY) {
			syslog_syserror(LOG_EMERG, "Unable to get random data from urandom");
			exit(EX_OSERR);
		}

		b2h(next.val, randoms, XSRF_TOKEN_BINARY_LENGTH);
		next.val[XSRF_TOKEN_HEX_LENGTH] = '\0';

		if ((tsock = accept(sock, NULL, NULL)) == -1) {
			syslog_syserror(LOG_ALERT, "Unable to accept incoming connection");
			exit(EX_OSERR);
		}

		if (recv(tsock, &received, sizeof(struct xsrft), 0) < 0) {
			syslog_syserror(LOG_ERR, "Unable to receive data from connection");
			next.val[0] = (char)0xff;
		} else {
			if ((now = time(NULL)) <= 0) {
				syslog(LOG_ERR, "Unable to retrieve UNIX time");
				next.val[0] = (char)0xff;
			} else if (received.val[0] == 0x00 || received.val[0] == 0xff) {
				session_calls = 0;
				if (now <= (login_attempts[login_number] + XSRFD_CERTAIN_BRUTE_FORCE_TIME)) {
					syslog(LOG_WARNING, "XSRFD brute force alarm tripped");
					if (sleep(XSRFD_CERTAIN_BRUTE_FORCE_SLOWDOWN) != 0) {
						next.val[0] = (char)0xff;
					}
				} else if (now <= (login_attempts[(login_number + XSRFD_CERTAIN_BRUTE_FORCE_COUNT - XSRFD_POSSIBLE_BRUTE_FORCE_COUNT) % XSRFD_CERTAIN_BRUTE_FORCE_COUNT] + XSRFD_POSSIBLE_BRUTE_FORCE_TIME)) {
					syslog(LOG_INFO, "XSRFD possible brute force alarm tripped");
					if (sleep(XSRFD_POSSIBLE_BRUTE_FORCE_SLOWDOWN) != 0) {
						next.val[0] = (char)0xff;
					}
				}

				login_attempts[login_number] = now;
				login_number = (login_number + 1) % XSRFD_CERTAIN_BRUTE_FORCE_COUNT;
			} else if (session_calls >= XSRFD_MAX_SESSION_CALLS || (now - login_attempts[(login_number + XSRFD_CERTAIN_BRUTE_FORCE_COUNT - 1) % XSRFD_CERTAIN_BRUTE_FORCE_COUNT]) >= XSRFD_MAX_SESSION_TIME) {
				syslog(LOG_INFO, "XSRF session has expired");
				next.val[0] = (char)0x00;
			}

			if (now < XSRFD_RECENT_DATE) {
				syslog(LOG_WARNING, "Received old UNIX time");
			}
	
			if (received.val[0] == 0xff) {
				next.val[0] = (char)0x00;
			} else if (received.val[0] != 0x00 && memcmp(&received, &stored, sizeof(struct xsrft)) != 0) {
				syslog(LOG_INFO, "Received bad XSRF token");
				next.val[0] = (char)0x00;
			}
		}

		if (send(tsock, &next, sizeof(struct xsrft), MSG_NOSIGNAL) < 0) {
			syslog_syserror(LOG_ERR, "Unable to send data to connection");
		}

		memcpy(&stored, &next, sizeof(struct xsrft));

		close(tsock);
	}
}

