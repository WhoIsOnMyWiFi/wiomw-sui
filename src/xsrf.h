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

#ifndef OPENWRT_SUI_XSRF_H
#define OPENWRT_SUI_XSRF_H

#define XSRF_SOCK_PATH "/var/run/xsrfd.sock"
#define XSRF_TOKEN_BINARY_LENGTH 24
#define XSRF_TOKEN_HEX_LENGTH XSRF_TOKEN_BINARY_LENGTH * 2

struct xsrft {
	char val[XSRF_TOKEN_HEX_LENGTH + 1];
};

#endif
