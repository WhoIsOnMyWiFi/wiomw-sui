#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([openwrt-sui], [0.2.17], [bugs@whoisonmywifi.com])
AC_CONFIG_SRCDIR([src/wifi_cgi.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([__isnan], [m])
AC_SEARCH_LIBS([__isinf], [m])
AC_CHECK_LIB([crypt], [crypt])
AC_CHECK_LIB([uci], [uci_alloc_context])
AC_ARG_WITH([fcgi],
   AC_HELP_STRING([--with-fcgi],
      [enable FastCGI support, default: check]),
   AS_CASE([${withval}],
      [no], AS_VAR_SET([use_fcgi], [no]),
      [yes], AS_VAR_SET([use_fcgi], [yes]),
      [check], AS_VAR_SET([use_fcgi], [check]),
      [""], AS_VAR_SET([use_fcgi], [yes]),
      AC_MSG_ERROR([Custom path to FastCGI installation is not yet supported])),
   AS_VAR_SET([use_fcgi], [check]))
AS_IF([test "x$use_fcgi" != xno],
   [AC_CHECK_LIB([fcgi],
      [FCGI_Accept])])
AS_IF([test "x$ac_cv_lib_fcgi_FCGI_Accept" == xno],
   AS_IF([test "x$use_fcgi" == xyes],
      AC_MSG_ERROR([FastCGI library not found, try --without-fcgi])))
PKG_CHECK_MODULES([CURL], [libcurl])
LIBCURL_CHECK_CONFIG
AS_IF([test "x$libcurl_protocol_HTTPS" != xyes || test "x$libcurl_feature_SSL" != xyes],
   [AC_MSG_ERROR([libcurl does not have HTTPS support enabled])])
AC_CHECK_LIB([yajl], [yajl_tree_parse])
AC_CHECK_LIB([polarssl], [sha512])

# Checks for header files.
AS_IF([test "x$ac_cv_lib_fcgi_FCGI_Accept" == xyes],
   [AC_CHECK_HEADERS([fcgi_stdio.h], , AC_MSG_ERROR([FastCGI headers not found]))])
AC_CHECK_HEADERS([arpa/inet.h shadow.h stddef.h stdint.h stdlib.h string.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
#AC_FUNC_STRNLEN
AC_CHECK_FUNCS([getspnam stpcpy strdup strerror strnlen strtoul])

AC_ARG_WITH([release],
	AC_HELP_STRING([--with-release=NUM],
		[Set release number, default: 1]),
	AS_IF([test "0${withval}" -ge 1],
	      AS_VAR_COPY([release_number], [{withval}]),
	      AC_MSG_ERROR([Release number must be an integer greater than 0.])),
	AS_VAR_SET([release_number], [1]))
AC_DEFINE_UNQUOTED([RELEASE_NUMBER], "${release_number}", [Release number])
	

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 www-static/Makefile
		 www-static/css/Makefile
		 www-static/js/Makefile])
AC_OUTPUT
