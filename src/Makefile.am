bin_PROGRAMS = sui.cgi xsrfd

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
		  urandom.h urandom.c

xsrfd_SOURCES = xsrfd.c \
		xsrf.h \
		b2h.h b2h.c \
		syslog_syserror.h syslog_syserror.c \
		urandom.h urandom.c

AM_CFLAGS=${CURL_CFLAGS}
sui_cgi_LDADD=${CURL_LIBS}

CLEANFILES = *.gcda *.gcno *.gcov

