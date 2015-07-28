# Copyright 2014, 2015 Who Is On My WiFi.
#
# This file is part of Who Is On My WiFi Linux.
#
# Who Is On My WiFi Linux is free software: you can redistribute it and/or
# modify it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or (at your
# option) any later version.
#
# Who Is On My WiFi Linux is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General
# Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# Who Is On My WiFi Linux.  If not, see <http://www.gnu.org/licenses/>.
#
# More information about Who Is On My WiFi Linux can be found at
# <http://www.whoisonmywifi.com/>.
#

bin_PROGRAMS = sui.cgi
sbin_PROGRAMS = xsrfd

sui_cgi_SOURCES = main_cgi.c \
		  password.h password.c \
		  string_helpers.h string_helpers.c \
		  wifi.h wifi.c \
		  wiomw.h wiomw.c \
		  mac.h mac.c \
		  reboot.h reboot.c \
		  wan_ip.h wan_ip.c \
		  lan_ip.h lan_ip.c \
		  update.h update.c \
		  range_check.h range_check.c \
		  version.h version.c \
		  xsrf.h xsrfc.h xsrfc.c \
		  urandom.h urandom.c \
		  syslog_syserror.h syslog_syserror.c \
		  dns.h dns.c \
		  check.h check.c

xsrfd_SOURCES = xsrfd.c \
		xsrf.h \
		b2h.h b2h.c \
		syslog_syserror.h syslog_syserror.c \
		urandom.h urandom.c

AM_CFLAGS=${CURL_CFLAGS}
sui_cgi_LDADD=${CURL_LIBS}

CLEANFILES = *.gcda *.gcno *.gcov

