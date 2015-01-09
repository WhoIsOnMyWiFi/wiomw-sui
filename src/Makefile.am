bin_PROGRAMS = sui.cgi
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
		  range_check.h range_check.c
AM_CFLAGS=${CURL_CFLAGS}
sui_cgi_LDADD=${CURL_LIBS}
