bin_PROGRAMS = aker

aker_SOURCES = main.c list.h compat.h
aker_CFLAGS = -D_GNU_SOURCE -DPREFIX='"$(prefix)"' -DSYSCONFDIR='"$(sysconfdir)"'
aker_LDADD = -lpcap
