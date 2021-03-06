#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT([libssh], 0.2.1-svn, [aris@0xbadc0de.be])
AM_INIT_AUTOMAKE(1.9)
AC_CONFIG_SRCDIR([sample.c])
AC_CONFIG_HEADER([config.h])

AM_MAINTAINER_MODE

# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBSSH_CURRENT=3
LIBSSH_AGE=1
LIBSSH_REVISION=0
AC_SUBST(LIBSSH_CURRENT)
AC_SUBST(LIBSSH_AGE)
AC_SUBST(LIBSSH_REVISION)

# Check for the OS.
AC_CANONICAL_HOST
case "$host" in
	*-apple*)
	LIBSSH_LDFLAGS="-prebind -seg1addr 0x3a000000 -headerpad_max_install_names"
	;;
	*)
	LIBSSH_LDFLAGS=""
	;;
esac
AC_SUBST(LIBSSH_LDFLAGS)

AC_MSG_CHECKING([version script options])
case "$host" in
	*-*-linux*)
	LIBSSH_VERS="$LIBSSH_LDFLAGS -Wl,--version-script,libssh.vers"
	;;
	*-*-gnu*)
	LIBSSH_VERS="$LIBSSH_LDFLAGS -Wl,--version-script,libssh.vers"
	;;
esac
AC_ARG_WITH([versioned-symbol],
	AC_HELP_STRING([--with-versioned-symbol],[Use versioned symbols]),
	[if test "$withval" = "yes"; then
	   LIBSSH_VERS="$LIBSSH_LDFLAGS -Wl,--version-script,libssh.vers"
	 else
	   LIBSSH_VERS=""
	 fi], [ : ])

AC_SUBST(LIBSSH_VERS)

enable_ssh1=${enable_ssh1:-"no"}
AC_ARG_ENABLE(ssh1, AC_HELP_STRING([--enable-ssh1], [enable SSH1 support]))
AC_MSG_CHECKING([for SSH1 support])
if test "$enable_ssh1" = "yes" ; then
  AC_DEFINE(HAVE_SSH1,1,[Define to 1 if you want to enable SSH1])
fi
AC_MSG_RESULT([$enable_ssh1])

# Checks for programs.
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_LIBTOOL
AC_C_BIGENDIAN

AC_CHECK_PROG([DOXYGEN], [doxygen], [yes], [no])
AM_CONDITIONAL([HAS_DOXYGEN], [test x"$DOXYGEN" = xyes])

# Checks for libraries.
with_gcrypt=${with_gcrypt:-"no"}
AC_ARG_WITH([libgcrypt],
    AC_HELP_STRING([--with-libgcrypt],[Use libgcrypt instead of libcrypto]),
    [if test "$withval" = "yes"; then
       with_gcrypt="yes"
       AC_CHECK_LIB([gcrypt], [gcry_md_open])
     fi], [ : ])

if test "$with_gcrypt" = "no"; then
  AC_CHECK_LIB([crypto], [BN_init])
fi

AC_CHECK_LIB([z], [deflateInit_])
AC_SEARCH_LIBS([hstrerror],[nsl resolv])
AC_SEARCH_LIBS([getaddrinfo],[nsl socket])
AC_SEARCH_LIBS([gethostbyname],[nsl resolv])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h netdb.h netinet/in.h stdlib.h string.h sys/socket.h \
sys/time.h termios.h unistd.h openssl/aes.h openssl/blowfish.h \
openssl/des.h zlib.h sys/poll.h stdint.h pty.h gcrypt.h])

#Warn user when no openssl available
if test "$with_gcrypt" = "no" && (test "$ac_cv_header_openssl_aes_h" != "yes" ||
				  test "$ac_cv_header_openssl_blowfish_h" != "yes"); then
        echo "Can't find valid openssl files [e.g openssl/aes.h]"
        echo "Please install Openssl-devel"
        exit
fi

#Warn user when no libgcrypt available
if test "$with_gcrypt" = "yes" && test "$ac_cv_header_gcrypt_h" != "yes"; then
	echo "Can't find valid libgcrypt files [e.g gcrypt.h]"
	echo "Please install libgcrypt-devel"
	exit
fi

#if ! test x"$ac_cv_header_zlib_h" != x"yes"; then
#        echo "Can't find zlib.h"
#        echo "Compression support won't be compiled in"
#fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_HEADER_TIME

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_TYPE_SIGNAL
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([endpwent getaddrinfo gethostbyname getpass memmove memset \
cfmakeraw select socket strchr strdup strerror strstr poll])

AC_CONFIG_FILES([Makefile
                 libssh/Makefile
		 include/Makefile
		 include/libssh/Makefile])
AC_OUTPUT
