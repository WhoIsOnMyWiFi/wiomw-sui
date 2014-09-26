#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([openwrt-sui], [0.0.1], [bugs@whoisonmywifi.com])
AC_CONFIG_SRCDIR([src/wifi_cgi.c])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([-Wall -Werror])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_SEARCH_LIBS([__isnan], [m])
AC_SEARCH_LIBS([__isinf], [m])
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
AC_CHECK_LIB([yajl], [yajl_tree_parse])

# Checks for header files.
AS_IF([test "x$ac_cv_lib_fcgi_FCGI_Accept" == xyes],
   [AC_CHECK_HEADERS([fcgi_stdio.h], , AC_MSG_ERROR([FastCGI headers not found]))])
AC_CHECK_HEADERS([stdlib.h string.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([stpcpy strdup strtoul])

AC_CONFIG_FILES([Makefile
                 src/Makefile
		 www-static/Makefile])
AC_OUTPUT
