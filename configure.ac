AC_PREREQ([2.69])
AC_INIT([aker], [1.1.0], [pme.lebleu@gmail.com], [], [https://github.com/pticon/aker])
AM_INIT_AUTOMAKE([-Wall -Werror foreign])

# Check for programs
AC_PROG_CC
AC_LANG(C)
AC_CONFIG_HEADERS([src/config.h])


# Configure options
AC_ARG_ENABLE([debug], AC_HELP_STRING([--enable-debug], [Enable debug compilation]),
[ if test "x$enableval" = "xyes"; then
	AC_DEFINE([DEBUG], [1], [Enable debug compilation, assertions, etc.])
fi ])
AC_PREFIX_DEFAULT(/usr/local)


# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_INT8_T
AC_TYPE_UINT8_T
AC_TYPE_INT16_T
AC_TYPE_UINT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_SIZE_T
AC_STRUCT_TM

AC_C_INLINE
AC_C_CONST

AC_FUNC_ALLOCA
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_FUNC_STAT
AC_FUNC_STRERROR_R
AC_FUNC_STRFTIME
AC_FUNC_VPRINTF



# Check for OS type
AC_CANONICAL_HOST
case "$host_os" in
	linux*)		OS=linux ;;
	freebsd*)	OS=freebsd ;;
	*)		AC_MSG_ERROR([Unknown or unsupported OS "$host_os".  Only "linux" and "freebsd" are supported in this version of Aker.]) ;;
esac
AC_SUBST([OS])

# Add defines relative to the OS type
if test "x$OS" = "xfreebsd"; then
	# In the built-in, the __FreeBSD__ macro is already define
	# AC_DEFINE([__FreeBSD__], [uname -r | cut -d . -f 1], [FreeBSD machine.])
	AC_DEFINE([DEFAULT_INTERFACE], ["em0"], [FreeBSD default interface.])
else if test "x$OS" = "xlinux"; then
	AC_DEFINE([__LINUX__], [1], [Linux machine.])
	AC_DEFINE([DEFAULT_INTERFACE], ["eth0"], [Linux default interface.])
else
	AC_MSG_ERROR([Unknown or unsupported OS "$host_os".  Only "linux" and "freebsd" are supported in this version of Aker.])
fi
fi


# Check for libraries
AC_CHECK_LIB(pcap, pcap_open_live, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_close, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_compile, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_perror, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_setfilter, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_freecode, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_breakloop, [], [echo "error: pcap library not found!"; exit -1])
AC_CHECK_LIB(pcap, pcap_datalink, [], [echo "error: pcap library not found!"; exit -1])


# Check for headers
AC_CHECK_HEADER(stdio.h, [], [echo "error: stdio.h not found!"; exit -1])
AC_CHECK_HEADER(unistd.h, [], [echo "error: unistd.h not found!"; exit -1])
AC_CHECK_HEADER(stdlib.h, [], [echo "error: stdlib.h not found!"; exit -1])
AC_CHECK_HEADER(stdarg.h, [], [echo "error: stdarg.h not found!"; exit -1])
AC_CHECK_HEADER(ctype.h, [], [echo "error: ctype.h not found!"; exit -1])
AC_CHECK_HEADER(string.h, [], [echo "error: string.h not found!"; exit -1])
AC_CHECK_HEADER(netdb.h, [], [echo "error: netdb.h not found!"; exit -1])
AC_CHECK_HEADER(signal.h, [], [echo "error: signal.h not found!"; exit -1])
AC_CHECK_HEADER(sys/types.h, [], [echo "error: sys/types.h not found!"; exit -1])
AC_CHECK_HEADER(sys/socket.h, [], [echo "error: sys/socket.h not found!"; exit -1])
AC_CHECK_HEADER(net/ethernet.h, [], [echo "error: net/ethernet.h not found!"; exit -1])
AC_CHECK_HEADER(netinet/in.h, [], [echo "error: netinet/in.h not found!"; exit -1])
AC_CHECK_HEADER(netinet/tcp.h, [], [echo "error: netinet/tcp.h not found!"; exit -1])
AC_CHECK_HEADER(netinet/udp.h, [], [echo "error: netinet/udp.h not found!"; exit -1])
AC_CHECK_HEADER(time.h, [], [echo "error: time.h not found!"; exit -1])
AC_CHECK_HEADER(errno.h, [], [echo "error: errno.h not found!"; exit -1])
AC_CHECK_HEADER(limits.h, [], [echo "error: limits.h not found!"; exit -1])

# Those headers cannot be used within FreeBSD
# => present but cannot be compiled
if test "x$OS" = "xlinux"; then
	AC_CHECK_HEADER(netinet/if_ether.h, [], [])
	AC_CHECK_HEADER(netinet/ip.h, [], [])
fi

AC_CHECK_HEADER(pcap.h, [], [echo "error: pcap.h not found!"; exit -1])


# Checks for library functions.
AC_CHECK_FUNCS([strlcat])


AC_OUTPUT([Makefile src/Makefile man/Makefile conf/Makefile])


AC_MSG_RESULT([
        $PACKAGE $VERSION
        ========

        prefix:                 ${prefix}
        libdir:                 ${libdir}
        sysconfdir:             ${sysconfdir}
        exec_prefix:            ${exec_prefix}
        bindir:                 ${bindir}
        datarootdir:            ${datarootdir}

        compiler:               ${CC}
        cflags:                 ${CFLAGS}
        ldflags:                ${LDFLAGS}
])
