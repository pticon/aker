# Makefile for aker
#
# Copyright (C) 2017 Pticon
# This is free software, licensed under the BSD 3-Clause License.
# See /LICENSE for more information.
#

TARGET=aker


CC:=gcc
LD:=gcc
CFLAGS:=-D_GNU_SOURCE -Wall -Wunused -Werror
LDFLAGS:=-lpcap
PREFIX := /usr/local


ifeq ($(DEBUG),1)
CFLAGS+=-O0 -g -DDEBUG
else
CFLAGS+=-O3 -DNDEBUG
endif


ifeq ($(VERBOSE),1)
Q=
echo-cmd =
else
Q=@
echo-cmd = @echo $(1)
endif


SRCS:=main.c
SRCS+=

OBJS:=$(SRCS:%.c=%.o)


all: $(TARGET)


$(TARGET): $(OBJS)
	$(call echo-cmd, "  LD   $@")
	$(Q)$(LD) -o $@ $^ $(LDFLAGS)


%.o: %.c
	$(call echo-cmd, "  CC   $@")
	$(Q)$(CC) $(CFLAGS) -c $< -o $@


.PHONY: clean test install uninstall

install: $(TARGET)
	$(call echo-cmd, "  INSTALL")
	$(Q)mkdir -p $(DESTDIR)$(PREFIX)/bin
	$(Q)cp $(TARGET) $(DESTDIR)$(PREFIX)/bin/$(TARGET)
	$(Q)mkdir -p $(DESTDIR)$(PREFIX)/etc
	$(Q)cp aker.conf $(DESTDIR)$(PREFIX)/etc/aker.conf

uninstall:
	$(call echo-cmd, "  UNINSTALL")
	$(Q)rm -f $(DESTDIR)$(PREFIX)/bin/$(TARGET) $(DESTDIR)$(PREFIX)/etc/aker.conf

test: $(TARGET)
	$(call echo-cmd, "  TEST")
	$(Q)sudo ./regress.py -a

clean:
	$(call echo-cmd, "  CLEAN")
	$(Q)rm -f $(TARGET) $(OBJS)
