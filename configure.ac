AC_INIT([libtelnet], [0.13], [http://github.com/elanthis/libtelnet/tree/master])

AM_INIT_AUTOMAKE

CFLAGS="$CFLAGS -std=gnu11"

AC_PROG_CC
AC_PROG_LIBTOOL

PKG_CHECK_MODULES(LIBCRYPTO, libcrypto)
PKG_CHECK_MODULES(LIBSSL, libssl)


# zlib support
AC_CHECK_LIB(z,deflate,ZLIB=yes,ZLIB=no)
if test "x$ZLIB" = "xyes" ; then
	LIBS="$LIBS -lz"
	AC_DEFINE(HAVE_ZLIB, 1, [We have zlib])
fi

AC_CONFIG_FILES([Makefile util/Makefile man/Makefile libtelnet.pc])
AC_OUTPUT
